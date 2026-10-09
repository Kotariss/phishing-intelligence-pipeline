import re
import time
from typing import List

try:
    from ..orchestrator.state import PhishingState, AgentStepTrace
    from ..brands.matcher import get_brand_registry
    from ..features.url_features import hostname, registrable_domain, is_ip_host, free_hosting_suffix, homograph_label, mask_url
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, AgentStepTrace
    from brands.matcher import get_brand_registry
    from features.url_features import hostname, registrable_domain, is_ip_host, free_hosting_suffix, homograph_label, mask_url


TRUSTED_REDIRECTORS = re.compile(
    r'(?i)^https?://(?:[a-z0-9-]+\.)*(?:login\.microsoftonline\.com/.*authorize\?|vk\.com/away\.php\?to=|'
    r'clck\.ru/|trk\.mail\.ru/c/|ok\.me/|tinyurl\.com/|search\.app/|bit\.ly/|t\.co/|goo\.gl/|is\.gd/|'
    r'cutt\.ly/|rebrand\.ly/|t\.ly/|google\.[a-z.]+/(?:url|amp)\?|l\.facebook\.com/l\.php|'
    r'www\.google\.[a-z.]+/url\?)'
)

EXECUTABLE_PAYLOADS = re.compile(
    r'(?i)\.(?:exe|msi|bat|cmd|ps1|vbs|hta|scr|iso|img|jar|lnk|apk)(?:[?#].*)?$'
)


class URLAgent:
    """Analyzes redirects, domain infrastructure, open redirect abuse and payload drops."""

    def __init__(self, brand_registry=None):
        self.registry = brand_registry or get_brand_registry()

    def run(self, state: PhishingState) -> PhishingState:
        t0 = time.time()
        initial_codes = set(state.reason_codes)
        state.execution_steps.append("url_agent: Inspecting network indicators")

        primary_urls: List[str] = [u for u in (state.scan_url, state.final_url) if u]
        if not primary_urls and state.raw_target.startswith(("http://", "https://")):
            primary_urls.append(state.raw_target)
        chain_urls = [h.url for h in state.redirect_chain if h.url]
        other_urls = list(state.discovered_urls_from_attachments)
        for link in state.network_evidence.get("links", []):
            other_urls += [link.get("url") or "", link.get("final_url") or "", link.get("download_url") or ""]
        all_urls = list(dict.fromkeys(u for u in primary_urls + chain_urls + other_urls if u and u.startswith("http")))

        net = {
            "redirect_count": len(state.redirect_chain),
            "urls_inspected": len(all_urls),
            "is_shortener_abuse": False,
            "is_rat_drop": False,
            "is_executable_drop": False,
            "is_dead_host": False,
            "is_punycode": False,
        }

        if len(state.redirect_chain) >= 2:
            state.add_reason("RC_REDIRECT_MULTI_HOP", f"{len(state.redirect_chain)} перенаправлений до {state.final_url}")

        js_cross = [h for h in state.redirect_chain if h.hop_type != "http_redirect"]
        if js_cross and state.final_url and state.scan_url and \
                registrable_domain(hostname(state.final_url)) != registrable_domain(hostname(state.scan_url)):
            state.add_reason("RC_REDIRECT_CROSS_DOMAIN_JS", f"JS/meta-редирект {hostname(state.scan_url)} → {hostname(state.final_url)}")

        for u in all_urls:
            if TRUSTED_REDIRECTORS.search(u):
                state.add_reason("RC_REDIRECT_ABUSE_TRUSTED", f"Доверенный редиректор: {u[:120]}")
                net["is_shortener_abuse"] = True
                break

        for u in all_urls:
            low = u.lower()
            if "screenconnect.clientsetup" in low or "screenconnect.windowsclient" in low:
                state.add_reason("RC_DROP_SCREENCONNECT_RAT", f"Загрузка ScreenConnect: {u[:160]}")
                net["is_rat_drop"] = True
            elif EXECUTABLE_PAYLOADS.search(u.split("?")[0]):
                state.add_reason("RC_DROP_EXECUTABLE_PAYLOAD", f"Ссылка на исполняемый файл: {u[:160]}")
                net["is_executable_drop"] = True

        if state.http_status is not None and (state.http_status == 0 or state.http_status >= 400) and primary_urls:
            state.add_reason("RC_EPHEMERAL_HOST_DEAD", f"HTTP статус {state.http_status} для {primary_urls[-1][:120]}")
            net["is_dead_host"] = True

        inspected_hosts = []
        for u in all_urls:
            h = hostname(u)
            if h and h not in inspected_hosts:
                inspected_hosts.append(h)
        primary_hosts = {hostname(u) for u in primary_urls}

        for h in inspected_hosts:
            if is_ip_host(h) and h in primary_hosts:
                state.add_reason("URL_IP_HOST", f"Хост-IP: {h}")
            decoded = homograph_label(h)
            if decoded:
                state.add_reason("BRAND_HOMOGRAPH_DOMAIN", f"IDN-омограф: {h} ({decoded})")
                net["is_punycode"] = True
            look = self.registry.find_lookalike_brand(h)
            if look:
                brand, token = look
                state.add_reason("BRAND_LOOKALIKE_DOMAIN", f"Домен {h} содержит '{token}' ({brand['display_name']}), но не входит в allowlist бренда")
                net.setdefault("lookalike_brand", brand["display_name"])
                net.setdefault("lookalike_host", h)

        final_host = hostname(state.final_url or "")
        suffix = free_hosting_suffix(final_host) if final_host else None
        if suffix:
            state.add_reason("URL_FREE_HOSTING", f"{final_host} размещён на {suffix}")

        net["final_domain"] = registrable_domain(final_host) if final_host else None
        state.network_evidence.update(net)

        added_codes = [c for c in state.reason_codes if c not in initial_codes]
        elapsed_ms = round((time.time() - t0) * 1000, 1)
        state.agent_traces.append(AgentStepTrace(
            agent_id="url_agent",
            agent_name="URL & Network Infrastructure Agent",
            icon="🌐",
            phase="Phase 2: Static & Network Inspection",
            status="TRIGGERED" if added_codes else "COMPLETED",
            duration_ms=elapsed_ms,
            reasoning=f"Инспекция {len(all_urls)} URL (основной: '{mask_url(state.final_url or state.scan_url or state.raw_target)[:200]}'). Анализ глубины и типа перенаправлений, злоупотребления доверенными редиректорами, доменов-двойников брендов, IDN-омографов, IP-хостов, бесплатного хостинга, полезных нагрузок (ScreenConnect, exe/msi/iso) и доступности хоста.",
            decision=f"Выявлено индикаторов сетевых угроз: {len(added_codes)} шт. " + (f"[{', '.join(added_codes)}]" if added_codes else "[Сетевых аномалий не обнаружено]"),
            tools_called=["RedirectChainAnalyzer", "LookalikeDomainDetector", "HomographDetector", "PayloadPatternMatcher"],
            findings=[
                {"label": "Количество хопов", "value": str(len(state.redirect_chain))},
                {"label": "Проверено URL", "value": str(len(all_urls))},
                {"label": "Домен-двойник бренда", "value": net.get("lookalike_host") or "Нет"},
                {"label": "Абуз сокращателей/OAuth", "value": "Да" if net["is_shortener_abuse"] else "Нет"},
                {"label": "Дроппер ScreenConnect", "value": "Да" if net["is_rat_drop"] else "Нет"},
                {"label": "Эфемерный/мертвый хост", "value": "Да" if net["is_dead_host"] else "Нет"}
            ],
            state_delta={"triggered_codes": added_codes}
        ))
        return state
