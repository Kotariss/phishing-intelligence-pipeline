import datetime
import re
import uuid
from typing import List, Optional, Tuple

try:
    import yara  # optional: used to self-validate generated rules
except ImportError:  # pragma: no cover - depends on environment
    yara = None

try:
    from ..features.url_features import is_ip_lookup_service
except (ImportError, ValueError):
    from features.url_features import is_ip_lookup_service


def yara_escape(value: str) -> str:
    """Escapes a value for a YARA text string; non-ASCII is emitted as UTF-8 \\xHH bytes."""
    out = []
    for byte in value.encode("utf-8"):
        ch = chr(byte)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif 0x20 <= byte < 0x7f:
            out.append(ch)
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out)


def _meta_str(value: str) -> str:
    return yara_escape(value)[:200]


def compile_check(rule_text: str) -> Tuple[bool, Optional[str]]:
    if yara is None:
        return True, None
    try:
        yara.compile(source=rule_text)
        return True, None
    except Exception as e:  # yara.SyntaxError and friends
        return False, str(e)


class YARAGenerator:
    """Generates content YARA rules for HTML pages / attachments / e-mails from sample-specific strings.

    Rules are produced only when the sample yields at least one highly specific string (exfiltration
    endpoint, kit marker, payload name, credential-post host) — a generic "contains password field"
    rule would fire on every login page."""

    def generate(self, state, rule_id: Optional[str] = None) -> Optional[str]:
        page = state.page_features or {}
        att = state.attachment_evidence or {}
        html_items = [i for i in att.get("attachments_analysis") or [] if i.get("kind") == "html"]
        if att.get("type") == "html":
            html_items.append(att)
        sources = [page] + html_items

        strings: List[Tuple[str, str]] = []  # (identifier, yara string definition)
        specific = 0

        bot_ids = sorted({t.split(":")[0] for s in sources for t in s.get("telegram_bot_tokens") or []})
        for i, bot in enumerate(bot_ids[:3]):
            strings.append((f"$tg{i}", f'"api.telegram.org/bot{yara_escape(bot)}:" ascii wide nocase'))
            specific += 1
        if not bot_ids and any(s.get("has_telegram_exfil") for s in sources):
            strings.append(("$tg_api", '"api.telegram.org/bot" ascii wide nocase'))
        hooks = sorted({w for s in sources for w in s.get("discord_webhooks") or []})
        for i, hook in enumerate(hooks[:3]):
            strings.append((f"$dc{i}", f'"{yara_escape(hook)}" ascii wide nocase'))
            specific += 1

        if "RC_DROP_SCREENCONNECT_RAT" in state.reason_codes:
            strings.append(("$sc", '"ScreenConnect.ClientSetup" ascii wide nocase'))
            specific += 1

        post_hosts = sorted({f.action_host for f in state.dom_forms if f.is_external_target and f.action_host})
        post_hosts += [u.split("/")[2] for s in sources for u in s.get("js_external_endpoints") or []
                       if u.count("/") >= 2 and not is_ip_lookup_service(u)]
        for i, host in enumerate(sorted(set(post_hosts))[:3]):
            strings.append((f"$post{i}", f'"{yara_escape(host)}" ascii wide nocase'))
            specific += 1

        title = (page.get("title") or att.get("title") or "").strip()
        if len(title) >= 8:
            strings.append(("$title", f'"{yara_escape(title[:80])}" ascii wide nocase'))

        has_pass = any(f.has_password for f in state.dom_forms) or page.get("has_password_field") or att.get("has_password_field")
        if has_pass:
            strings.append(("$pass", r'/type\s*=\s*["\']?password/ nocase'))

        if specific == 0:
            return None

        strong_ids = [s for s, _ in strings if s.startswith(("$tg", "$dc", "$sc")) and s != "$tg_api"]
        weak_ids = [s for s, _ in strings if s.startswith("$post")]
        context_ids = [s for s, _ in strings if s in ("$title", "$pass", "$tg_api")]
        if strong_ids:
            # exfiltration endpoints / payload names are unique to the actor
            used = strong_ids
            condition = f"filesize < 5MB and 1 of ({', '.join(used)})"
        elif context_ids:
            # a host name alone also appears in benign pages that merely link to it
            used = weak_ids + context_ids
            condition = f"filesize < 5MB and 1 of ({', '.join(weak_ids)}) and 1 of ({', '.join(context_ids)})"
        else:
            return None
        strings = [(ident, definition) for ident, definition in strings if ident in used]  # YARA rejects unreferenced strings

        name_suffix = re.sub(r'[^A-Za-z0-9_]', '_', rule_id or uuid.uuid4().hex[:8])
        brand = state.brand_evidence.detected_brand_name or "Generic"
        body = "\n".join(f"        {ident} = {definition}" for ident, definition in strings)
        rule = f"""/* Phishing Intelligence Pipeline — generated from incident {_meta_str(state.incident_id)} */
rule DrWeb_Phish_{name_suffix}
{{
    meta:
        description = "{_meta_str('Phishing content: ' + ', '.join(sorted(state.reason_codes))[:150])}"
        author = "Phishing Intelligence Pipeline"
        date = "{datetime.date.today().isoformat()}"
        target_brand = "{_meta_str(brand)}"
        risk_score = "{state.risk_score:.2f}"
        source_incident = "{_meta_str(state.incident_id)}"
    strings:
{body}
    condition:
        {condition}
}}
"""
        ok, err = compile_check(rule)
        if not ok:
            state.execution_steps.append(f"yara_gen: generated rule rejected by YARA compiler: {err}")
            return None
        return rule
