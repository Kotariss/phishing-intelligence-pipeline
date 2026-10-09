"""
Reference evaluator for lar-rule-v1 L-signatures.

This is deliberately tiny and dependency-free: it is the behaviour the *local* anti-spam engine
has to reproduce. A rule matches a feature record when ALL predicates in `all_of` hold and,
if `any_of` is non-empty, at least one of them holds. Unknown predicate types never match
(fail-closed for detection, which keeps the false-positive rate at zero for unsupported rules).

Feature record (what the light engine extracts cheaply from a message / page):
    url, host, path, title, brand_context, has_password, forms[{has_password,has_card,is_external,action_host}],
    dom_hash, js_endpoint_hosts[], telegram_bot_ids[], discord_webhook_ids[], attachment_names[],
    attachment_html_password, attachment_html_redirect, sender_name, sender_domain, reply_to_mismatch,
    link_urls[]
"""
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    from ..features.url_features import hostname, registrable_domain
    from ..brands.matcher import alias_pattern, normalize_display_text
except (ImportError, ValueError):
    from features.url_features import hostname, registrable_domain
    from brands.matcher import alias_pattern, normalize_display_text


def _rx(pattern: str) -> Optional[re.Pattern]:
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None


def _keyword_hit(keywords: List[str], text: str) -> bool:
    text, _ = normalize_display_text(text or "")
    return any(kw and alias_pattern(kw).search(text) for kw in keywords or [])


def _host_allowed(host: str, patterns: List[str]) -> bool:
    for p in patterns or []:
        rx = _rx(p)
        if rx and rx.search(host or ""):
            return True
    return False


def evaluate_condition(cond: Dict[str, Any], rec: Dict[str, Any]) -> bool:
    ctype = cond.get("type")

    if ctype == "brand_mismatch":
        if cond.get("scope") == "sender":
            text, host = rec.get("sender_name", ""), rec.get("sender_domain", "")
            if not host:
                return False
        else:
            text, host = rec.get("brand_context", ""), rec.get("host", "")
        if not _keyword_hit(cond.get("keywords") or [cond.get("brand", "")], text):
            return False
        return not _host_allowed(host, cond.get("allowed_domain_patterns", []))

    if ctype == "host_brand_token":
        host = rec.get("host", "")
        token = (cond.get("token") or "").lower()
        if not token or token not in re.sub(r'[^a-z0-9.]', '', host):
            return False
        return not _host_allowed(host, cond.get("allowed_domain_patterns", []))

    if ctype == "dom_form_structure":
        forms = rec.get("forms") or []
        need_pass = cond.get("has_password_input", False)
        need_ext = cond.get("action_is_external", False)
        need_card = cond.get("has_card_input", False)
        for f in forms:
            if need_pass and not f.get("has_password"):
                continue
            if need_ext and not f.get("is_external"):
                continue
            if need_card and not f.get("has_card"):
                continue
            return True
        # password inputs rendered outside a <form> element
        return bool(need_pass and not need_ext and not need_card and rec.get("has_password"))

    if ctype == "url_path_pattern":
        rx = _rx(cond.get("regex", ""))
        if not rx:
            return False
        paths = [rec.get("path", "")] + [urlparse(u).path for u in rec.get("link_urls") or []]
        return any(p and rx.search(p) for p in paths)

    if ctype == "dom_structural_hash":
        return bool(rec.get("dom_hash")) and rec.get("dom_hash") == cond.get("hash")

    if ctype == "exfil_endpoint":
        kind, value = cond.get("kind"), cond.get("value")
        if kind == "telegram":
            return value in (rec.get("telegram_bot_ids") or [])
        if kind == "discord":
            return value in (rec.get("discord_webhook_ids") or [])
        if kind == "host":
            return value in (rec.get("js_endpoint_hosts") or []) or \
                any(f.get("action_host") and registrable_domain(f["action_host"]) == value for f in rec.get("forms") or [])
        return False

    if ctype == "attachment_name_pattern":
        rx = _rx(cond.get("regex", ""))
        return bool(rx) and any(rx.search(n or "") for n in rec.get("attachment_names") or [])

    if ctype == "attachment_html_feature":
        feature = cond.get("feature")
        if feature == "password_input":
            return bool(rec.get("attachment_html_password"))
        if feature == "external_redirect":
            return bool(rec.get("attachment_html_redirect"))
        return False

    if ctype == "title_keyword":
        return _keyword_hit(cond.get("keywords") or [], rec.get("title", ""))

    if ctype == "reply_to_mismatch":
        return bool(rec.get("reply_to_mismatch"))

    return False  # unknown predicate: never matches


def rule_matches(rule: Dict[str, Any], rec: Dict[str, Any]) -> bool:
    preds = rule.get("predicates") or {}
    all_of = preds.get("all_of") or []
    any_of = preds.get("any_of") or []
    if not all_of and not any_of:
        return False
    if not all(evaluate_condition(c, rec) for c in all_of):
        return False
    return not any_of or any(evaluate_condition(c, rec) for c in any_of)


# ------------------------------------------------------------------ feature records
def _telegram_ids(tokens: List[str]) -> List[str]:
    return sorted({t.split(":")[0] for t in tokens or [] if t})


def build_record(url: str = "", page: Optional[Dict[str, Any]] = None, attachment: Optional[Dict[str, Any]] = None,
                 forms: Optional[List[Dict[str, Any]]] = None, dom_hash: Optional[str] = None,
                 extra_names: Optional[List[str]] = None) -> Dict[str, Any]:
    page = page or {}
    att = attachment or {}
    host = hostname(url) if url else ""
    html_items = [i for i in att.get("attachments_analysis") or [] if i.get("kind") == "html"]
    if att.get("type") == "html":
        html_items.append(att)
    tg = list(page.get("telegram_bot_tokens") or []) + [t for i in html_items for t in i.get("telegram_bot_tokens") or []]
    dc = list(page.get("discord_webhooks") or []) + [w for i in html_items for w in i.get("discord_webhooks") or []]
    names = list(extra_names or []) + [m.get("filename") or "" for m in att.get("attachments_meta") or []]
    if att.get("filename"):
        names.append(att["filename"])
    title = page.get("title") or att.get("title") or ""
    return {
        "url": url or "",
        "host": host,
        "path": urlparse(url).path if url else "",
        "title": title,
        # where a page *presents itself* as a brand: title and top headings (not footers / payment logos)
        "brand_context": page.get("brand_context_text") or att.get("brand_context_text") or title,
        "has_password": bool(page.get("has_password_field")),
        "forms": [{"has_password": bool(f.get("has_password")), "has_card": bool(f.get("has_card")),
                   "is_external": bool(f.get("is_external") or f.get("is_external_target")),
                   "action_host": f.get("action_host") or ""} for f in (forms if forms is not None else page.get("forms") or [])],
        "dom_hash": dom_hash or page.get("dom_structural_hash"),
        "js_endpoint_hosts": sorted({registrable_domain(hostname(u)) for u in page.get("js_external_endpoints") or [] if hostname(u)}),
        "telegram_bot_ids": _telegram_ids(tg),
        "discord_webhook_ids": sorted({w.rstrip("/").split("/")[-1] if w.count("/") > 3 else w for w in dc}),
        "attachment_names": [n for n in names if n],
        "attachment_html_password": any(i.get("has_password_field") or any(f.get("has_card") for f in i.get("forms") or [])
                                        for i in html_items),
        "attachment_html_redirect": any(i.get("meta_refresh") or i.get("js_redirects") for i in html_items),
        "sender_name": att.get("from_name") or "",
        "sender_domain": att.get("from_domain") or "",
        "reply_to_mismatch": bool(att.get("reply_to_mismatch")),
        "link_urls": list(att.get("links") or [])[:50],
    }


def record_from_state(state) -> Dict[str, Any]:
    url = state.final_url or state.scan_url or (state.raw_target if str(state.raw_target).startswith("http") else "")
    forms = [{"has_password": f.has_password, "has_card": f.has_card, "is_external": f.is_external_target,
              "action_host": f.action_host} for f in state.dom_forms]
    return build_record(url=url, page=state.page_features, attachment=state.attachment_evidence, forms=forms,
                        dom_hash=state.dom_structural_hash, extra_names=[os.path.basename(str(state.raw_target))])
