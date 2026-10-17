import re
import time
from typing import List

try:
    from ..orchestrator.state import PhishingState, AgentStepTrace
    from ..brands.matcher import get_brand_registry
    from ..features.url_features import hostname, registrable_domain, is_ip_host, free_hosting_suffix, homograph_label, mask_url, confusable_skeleton
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, AgentStepTrace
    from brands.matcher import get_brand_registry
    from features.url_features import hostname, registrable_domain, is_ip_host, free_hosting_suffix, homograph_label, mask_url, confusable_skeleton


TRUSTED_REDIRECTORS = re.compile(
    r'(?i)^https?://(?:[a-z0-9-]+\.)*(?:login\.microsoftonline\.com/.*authorize\?|vk\.com/away\.php\?to=|'
    r'clck\.ru/|trk\.mail\.ru/c/|ok\.me/|tinyurl\.com/|search\.app/|bit\.ly/|t\.co/|goo\.gl/|is\.gd/|'
    r'cutt\.ly/|rebrand\.ly/|t\.ly/|google\.[a-z.]+/(?:url|amp)\?|l\.facebook\.com/l\.php|'
    r'www\.google\.[a-z.]+/url\?|googleads\.g\.doubleclick\.net/pcs/click|ad\.doubleclick\.net/ddm/clk)'
)

IPFS_LINK = re.compile(r'(?i)^https?://(?:[^/]+/ipfs/|[a-z0-9]{40,}\.ipfs\.[a-z.]+/|[^/]*(?:ipfs\.io|dweb\.link|w3s\.link|cloudflare-ipfs\.com|nftstorage\.link|fleek\.co)/)')

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
            state.add_reason("RC_REDIRECT_MULTI_HOP", f"{len(state.redirect_chain)} перенаправлений до {state.final_url}",
                             {"type": "chain", "value": [h.url for h in state.redirect_chain] + [state.final_url or ""], "label": "Цепочка перенаправлений"})

        js_cross = [h for h in state.redirect_chain if h.hop_type != "http_redirect"]
        if js_cross and state.final_url and state.scan_url and \
                registrable_domain(hostname(state.final_url)) != registrable_domain(hostname(state.scan_url)):
            state.add_reason("RC_REDIRECT_CROSS_DOMAIN_JS", f"JS/meta-редирект {hostname(state.scan_url)} → {hostname(state.final_url)}", {"type": "url", "value": state.final_url, "label": "Финальная страница"})

        for u in all_urls:
            if TRUSTED_REDIRECTORS.search(u):
                state.add_reason("RC_REDIRECT_ABUSE_TRUSTED", f"Доверенный редиректор: {u[:120]}", {"type": "url", "value": u, "label": "Ссылка через доверенный сервис"})
                net["is_shortener_abuse"] = True
                break

        for u in all_urls:
            low = u.lower()
            if "screenconnect.clientsetup" in low or "screenconnect.windowsclient" in low:
                state.add_reason("RC_DROP_SCREENCONNECT_RAT", f"Загрузка ScreenConnect: {u[:160]}", {"type": "url", "value": u, "label": "Загружаемый файл"})
                net["is_rat_drop"] = True
            elif EXECUTABLE_PAYLOADS.search(u.split("?")[0]):
                state.add_reason("RC_DROP_EXECUTABLE_PAYLOAD", f"Ссылка на исполняемый файл: {u[:160]}", {"type": "url", "value": u, "label": "Загружаемый файл"})
                net["is_executable_drop"] = True

        if state.http_status is not None and (state.http_status == 0 or state.http_status >= 400) and primary_urls:
            state.add_reason("RC_EPHEMERAL_HOST_DEAD", f"HTTP статус {state.http_status} для {primary_urls[-1][:120]}", {"type": "url", "value": primary_urls[-1], "label": "Недоступный адрес"})
            net["is_dead_host"] = True

        inspected_hosts = []
        for u in all_urls:
            h = hostname(u)
            if h and h not in inspected_hosts:
                inspected_hosts.append(h)
        primary_hosts = {hostname(u) for u in primary_urls}
        lure_hosts = primary_hosts | {hostname(u) for u in chain_urls}

        for h in inspected_hosts:
            if is_ip_host(h) and h in primary_hosts:
                state.add_reason("URL_IP_HOST", f"Хост-IP: {h}", {"type": "url", "value": h, "label": "IP-адрес вместо домена"})
            decoded = homograph_label(h)
            if decoded:
                state.add_reason("BRAND_HOMOGRAPH_DOMAIN", f"IDN-омограф: {h} ({decoded})", {"type": "url", "value": f"{h} → {decoded}", "label": "Punycode → отображение"})
                net["is_punycode"] = True
            # Letters that only look Latin ('аррӏе.com' entirely in Cyrillic, 'g00gle.com'): compare the skeleton.
            skeleton = confusable_skeleton(h)
            imitated = None
            if skeleton and not self.registry.find_brand_for_domain(h):
                imitated = self.registry.find_brand_for_domain(skeleton)
                if not imitated and h in lure_hosts:
                    hit = self.registry.find_lookalike_brand(skeleton)
                    imitated = hit[0] if hit else None
            if imitated:
                idn = h.startswith("xn--") or ".xn--" in h
                if idn and "BRAND_HOMOGRAPH_DOMAIN" not in state.reason_codes:
                    state.add_reason("BRAND_HOMOGRAPH_DOMAIN", f"IDN-омограф: {h} читается как {skeleton} ({imitated['display_name']})",
                                     {"type": "url", "value": f"{h} → {skeleton}", "label": "Punycode → отображение"})
                    net["is_punycode"] = True
                elif not idn and h in lure_hosts:
                    state.add_reason("BRAND_LOOKALIKE_DOMAIN", f"Домен {h} читается как {skeleton} ({imitated['display_name']}): подмена похожих символов",
                                     {"type": "url", "value": f"{h} → {skeleton}", "label": f"Домен-двойник {imitated['display_name']}"})
                if h in lure_hosts:
                    net.setdefault("lookalike_brand", imitated["display_name"])
                    net.setdefault("lookalike_host", h)
            # Look-alike domains are judged only on the lure path (primary link, landing page, redirect
            # chain): newsletters legitimately link to third-party sites named after products.
            look = self.registry.find_lookalike_brand(h) if h in lure_hosts else None
            if look:
                brand, token = look
                state.add_reason("BRAND_LOOKALIKE_DOMAIN", f"Домен {h} содержит '{token}' ({brand['display_name']}), но не входит в allowlist бренда",
                                 {"type": "url", "value": h, "label": f"Домен-двойник {brand['display_name']}"})
                net.setdefault("lookalike_brand", brand["display_name"])
                net.setdefault("lookalike_host", h)

        final_host = hostname(state.final_url or "")
        suffix = free_hosting_suffix(final_host) if final_host else None
        if suffix:
            state.add_reason("URL_FREE_HOSTING", f"{final_host} размещён на {suffix}", {"type": "url", "value": state.final_url, "label": "Страница на бесплатном хостинге"})

        # IPFS gateways: content addressed by hash, out of reach of hosting takedowns.
        ipfs = next((u for u in all_urls if IPFS_LINK.search(u)), None)
        if ipfs:
            state.add_reason("URL_IPFS_LINK", f"Ссылка на IPFS: {ipfs[:120]}", {"type": "url", "value": ipfs, "label": "Ссылка на шлюз IPFS"})
        # No landing page (offline attachment): the call-to-action link itself is judged for free hosting.
        if not suffix and not final_host and not ipfs:
            for u in state.discovered_urls_from_attachments:
                s_ = free_hosting_suffix(hostname(u))
                if s_ and not self.registry.find_brand_for_domain(u):
                    state.add_reason("URL_FREE_HOSTING", f"Ссылка из вложения ведёт на {hostname(u)} ({s_})",
                                     {"type": "url", "value": u, "label": "Ссылка на бесплатный хостинг"})
                    break

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
