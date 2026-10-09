import re
import time
from typing import Dict, Any, List
from urllib.parse import urlparse
try:
    from ..orchestrator.state import PhishingState, AgentStepTrace
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, AgentStepTrace


TRUSTED_SHORTENERS_AND_OAUTH = re.compile(
    r'(?i)^(?:https?://)?(?:login\.microsoftonline\.com/.*authorize\?|vk\.com/away\.php\?to=|clck\.ru/|trk\.mail\.ru/c/|ok\.me/|tinyurl\.com/|search\.app/|bit\.ly/|t\.co/)'
)

EXECUTABLE_PAYLOADS = re.compile(
    r'(?i)\.(?:exe|msi|bat|cmd|ps1|vbs|hta|scr|iso|img)(?:\?.*)?$'
)

class URLAgent:
    """Analyzes redirects, domain infrastructure, open redirect abuse and payload drops."""

    def run(self, state: PhishingState) -> Dict[str, Any]:
        t0 = time.time()
        initial_codes = set(state.reason_codes)
        state.execution_steps.append("url_agent: Inspecting network indicators")
        reasons = list(state.reason_codes)
        net_evidence: Dict[str, Any] = {
            "redirect_count": len(state.redirect_chain),
            "is_shortener_abuse": False,
            "is_rat_drop": False,
            "is_executable_drop": False,
            "is_dead_host": False,
            "is_punycode": False
        }

        urls_to_check = [state.raw_target]
        if state.final_url and state.final_url != state.raw_target:
            urls_to_check.append(state.final_url)
        for hop in state.redirect_chain:
            urls_to_check.append(hop.url)

        # 1. Check redirect hops
        if len(state.redirect_chain) >= 2:
            reasons.append("RC_REDIRECT_MULTI_HOP")
            net_evidence["redirect_hops_exceeded"] = True

        # 2. Check trusted redirect abuse
        for u in urls_to_check:
            if u and TRUSTED_SHORTENERS_AND_OAUTH.search(u):
                reasons.append("RC_REDIRECT_ABUSE_TRUSTED")
                net_evidence["is_shortener_abuse"] = True
                break

        # 3. Check payload drops
        for u in urls_to_check:
            if not u:
                continue
            u_low = u.lower()
            if "screenconnect.clientsetup" in u_low:
                reasons.append("RC_DROP_SCREENCONNECT_RAT")
                net_evidence["is_rat_drop"] = True
            elif EXECUTABLE_PAYLOADS.search(u):
                reasons.append("RC_DROP_EXECUTABLE_PAYLOAD")
                net_evidence["is_executable_drop"] = True

        # 4. Check dead/ephemeral host
        if state.http_status in (0, 404, 502, 503, 521, 523):
            reasons.append("RC_EPHEMERAL_HOST_DEAD")
            net_evidence["is_dead_host"] = True

        # 5. Check homograph/punycode
        if state.final_url and "xn--" in state.final_url:
            reasons.append("BRAND_HOMOGRAPH_DOMAIN")
            net_evidence["is_punycode"] = True

        state.network_evidence = net_evidence
        state.reason_codes = sorted(list(set(reasons)))
        
        added_codes = [c for c in state.reason_codes if c not in initial_codes]
        elapsed_ms = round((time.time() - t0) * 1000, 1)
        state.agent_traces.append(AgentStepTrace(
            agent_id="url_agent",
            agent_name="URL & Network Infrastructure Agent",
            icon="🌐",
            phase="Phase 2: Static & Network Inspection",
            status="TRIGGERED" if added_codes else "COMPLETED",
            duration_ms=elapsed_ms,
            reasoning=f"Инспекция сетевой инфраструктуры объекта '{state.final_url or state.raw_target}'. Анализ глубины перенаправлений, злоупотребления доверенными редиректами/сокращателями, поиск полезных нагрузок RAT (ScreenConnect, exe/msi/iso) и доступности хоста.",
            decision=f"Выявлено индикаторов сетевых угроз: {len(added_codes)} шт. " + (f"[{', '.join(added_codes)}]" if added_codes else "[Сетевых аномалий не обнаружено]"),
            tools_called=["RedirectChainAnalyzer", "PayloadPatternMatcher", "EphemeralHostDetector"],
            findings=[
                {"label": "Количество хопов", "value": str(len(state.redirect_chain))},
                {"label": "Абуз сокращателей/OAuth", "value": "Да" if net_evidence.get("is_shortener_abuse") else "Нет"},
                {"label": "Дроппер Remote Access RAT", "value": "Да" if net_evidence.get("is_rat_drop") else "Нет"},
                {"label": "Дроп исполняемого файла", "value": "Да" if net_evidence.get("is_executable_drop") else "Нет"},
                {"label": "Эфемерный/мертвый хост", "value": "Да" if net_evidence.get("is_dead_host") else "Нет"}
            ],
            state_delta={
                "triggered_codes": added_codes,
                "network_evidence": net_evidence
            }
        ))

        return state.model_dump()
