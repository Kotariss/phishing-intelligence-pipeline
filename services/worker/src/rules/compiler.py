import datetime
import os
import re
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    from ..brands.matcher import get_brand_registry
    from ..features.url_features import generalize_path, registrable_domain
    from ..features.file_names import DOUBLE_EXT_PATTERN
    from .engine import record_from_state
except (ImportError, ValueError):
    from brands.matcher import get_brand_registry
    from features.url_features import generalize_path, registrable_domain
    from features.file_names import DOUBLE_EXT_PATTERN
    from rules.engine import record_from_state


SCHEMA_URL = "https://drweb.com/schemas/lar-rule-v1.json"
CYRILLIC_TO_LATIN = {
    "А": "A", "Б": "B", "В": "V", "Г": "G", "Д": "D", "Е": "E", "Ё": "E", "Ж": "ZH", "З": "Z",
    "И": "I", "Й": "Y", "К": "K", "Л": "L", "М": "M", "Н": "N", "О": "O", "П": "P", "Р": "R",
    "С": "S", "Т": "T", "У": "U", "Ф": "F", "Х": "KH", "Ц": "TS", "Ч": "CH", "Ш": "SH", "Щ": "SCH",
    "Ъ": "", "Ы": "Y", "Ь": "", "Э": "E", "Ю": "YU", "Я": "YA"
}


def brand_tag(brand: Optional[str]) -> str:
    latin = "".join(CYRILLIC_TO_LATIN.get(c, c) for c in (brand or "GEN").upper())
    return "".join(c for c in latin if c.isalnum() and c.isascii())[:10] or "GEN"


class LSignatureCompiler:
    """Distils the evidence of one incident into a compact, domain-independent lar-rule-v1 L-signature.

    The rule describes the *technique* (brand shown off-domain + credential form, exfiltration channel,
    payload drop, HTML attachment, sender spoofing) so it survives domain / URL rotation. Instance-specific
    fingerprints are attached as optional `any_of` alternatives or as campaign metadata only."""

    def __init__(self, brand_registry=None):
        self.registry = brand_registry or get_brand_registry()

    # -------------------------------------------------------------- predicates
    def _brand_condition(self, brand_id: str, scope: str = "page") -> Optional[Dict[str, Any]]:
        b = self.registry.by_id.get(brand_id)
        if not b:
            return None
        keywords = [k for k in self.registry.brand_keywords(brand_id) if len(k) >= 4 or not k.isascii()]
        if not keywords:
            return None
        return {
            "type": "brand_mismatch",
            "scope": scope,
            "brand": b["display_name"],
            "keywords": keywords,
            "allowed_domain_patterns": b.get("allowed_domain_patterns", [])
        }

    @staticmethod
    def _form_condition(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        forms = rec.get("forms") or []
        if any(f["has_password"] for f in forms) or rec.get("has_password"):
            return {"type": "dom_form_structure", "has_password_input": True,
                    "action_is_external": any(f["has_password"] and f["is_external"] for f in forms)}
        if any(f["has_card"] for f in forms):
            return {"type": "dom_form_structure", "has_card_input": True}
        return None

    @staticmethod
    def _fingerprint_conditions(state, rec: Dict[str, Any]) -> List[Dict[str, Any]]:
        conds: List[Dict[str, Any]] = []
        if state.dom_structural_hash and (state.page_features.get("tags_count") or 0) >= 15:
            conds.append({"type": "dom_structural_hash", "hash": state.dom_structural_hash})
        url = state.final_url or ""
        if url.startswith("http"):
            pattern = generalize_path(urlparse(url).path)
            if pattern:
                conds.append({"type": "url_path_pattern", "regex": pattern})
        for host in rec.get("js_endpoint_hosts") or []:
            conds.append({"type": "exfil_endpoint", "kind": "host", "value": host})
        posted = {registrable_domain(f["action_host"]) for f in rec.get("forms") or []
                  if f.get("is_external") and f.get("action_host")}
        for host in sorted(posted):
            conds.append({"type": "exfil_endpoint", "kind": "host", "value": host})
        return conds

    # -------------------------------------------------------------------- main
    def compile(self, state) -> Optional[Dict[str, Any]]:
        codes = set(state.reason_codes)
        rec = record_from_state(state)
        brand_id = state.brand_evidence.brand_id
        brand_name = state.brand_evidence.detected_brand_name or "Generic"
        all_of: List[Dict[str, Any]] = []
        any_of: List[Dict[str, Any]] = []
        kind = None

        if rec["telegram_bot_ids"] or rec["discord_webhook_ids"]:
            kind = "exfil_channel"
            if rec["telegram_bot_ids"]:
                any_of += [{"type": "exfil_endpoint", "kind": "telegram", "value": v} for v in rec["telegram_bot_ids"]]
            any_of += [{"type": "exfil_endpoint", "kind": "discord", "value": v} for v in rec["discord_webhook_ids"]]
        elif codes & {"RC_DROP_SCREENCONNECT_RAT", "RC_DROP_EXECUTABLE_PAYLOAD"}:
            kind = "payload_drop"
            urls = [h.url for h in state.redirect_chain] + [state.final_url or "", state.scan_url or ""]
            urls += [l.get("download_url") or "" for l in state.network_evidence.get("links", [])]
            names = sorted({os.path.basename(urlparse(u).path) for u in urls if u and re.search(
                r'(?i)\.(exe|msi|bat|cmd|ps1|vbs|hta|scr|iso|img|jar|lnk|apk)$', urlparse(u).path)})
            if "RC_DROP_SCREENCONNECT_RAT" in codes:
                any_of.append({"type": "url_path_pattern", "regex": r"ScreenConnect\.(?:ClientSetup|WindowsClient)[^/]*\.(?:exe|msi)$"})
            any_of += [{"type": "url_path_pattern", "regex": re.escape(n) + "$"} for n in names[:5]]
        elif "BRAND_IMPERSONATION_CONFIRMED" in codes and brand_id and self._form_condition(rec):
            kind = "brand_credential_phish"
            all_of += [self._brand_condition(brand_id), self._form_condition(rec)]
        elif "BRAND_LOOKALIKE_DOMAIN" in codes and self._form_condition(rec):
            kind = "lookalike_credential_phish"
            host = state.network_evidence.get("lookalike_host") or rec["host"]
            look = self.registry.find_lookalike_brand(host)
            if look:
                brand, token = look
                brand_name = brand["display_name"]
                all_of += [{"type": "host_brand_token", "token": token,
                            "allowed_domain_patterns": brand.get("allowed_domain_patterns", [])},
                           self._form_condition(rec)]
        elif codes & {"ATTACH_OFFLINE_FORM", "ATTACH_HTML_REDIRECTOR"}:
            kind = "html_attachment"
            feature = "password_input" if "ATTACH_OFFLINE_FORM" in codes else "external_redirect"
            all_of.append({"type": "attachment_html_feature", "feature": feature})
            if brand_id and state.brand_evidence.brand_impersonation_confirmed:
                cond = self._brand_condition(brand_id)
                if cond:
                    any_of.append({"type": "title_keyword", "keywords": cond["keywords"]})
            any_of += self._fingerprint_conditions(state, rec)
            if not any_of:
                any_of.append({"type": "attachment_name_pattern", "regex": r"\.(?:s?html?|svg)$"})
        elif "RC_LURE_DOUBLE_EXTENSION" in codes:
            kind = "attachment_lure"
            any_of.append({"type": "attachment_name_pattern", "regex": DOUBLE_EXT_PATTERN.pattern.replace("(?i)", "")})
        elif "RC_BRAND_SPOOF_DISPLAYNAME" in codes:
            sender_brand = self.registry.find_brand_in_text(rec["sender_name"])
            cond = self._brand_condition(sender_brand[0]["brand_id"], scope="sender") if sender_brand else None
            if cond:
                kind = "sender_spoof"
                brand_name = sender_brand[0]["display_name"]
                all_of.append(cond)
                if rec["reply_to_mismatch"]:
                    any_of.append({"type": "reply_to_mismatch"})
                any_of += self._fingerprint_conditions(state, rec)
                if not any_of:
                    kind = None
                    all_of = []
        else:
            form = self._form_condition(rec)
            fps = self._fingerprint_conditions(state, rec)
            if form and fps:
                kind = "generic_credential_phish"
                all_of.append(form)
                any_of += fps

        all_of = [c for c in all_of if c]
        if not kind or not (all_of or any_of):
            return None

        risk = state.risk_score
        rule_id = f"LAR-{datetime.date.today().year}-{brand_tag(brand_name)}-{uuid.uuid4().hex[:6].upper()}"
        return {
            "$schema": SCHEMA_URL,
            "rule_id": rule_id,
            "name": f"{brand_name} — {kind.replace('_', ' ')}",
            "kind": kind,
            "target_brand": brand_name,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "version": 1,
            "scope": {
                "check_urls": any(c["type"] in ("url_path_pattern", "host_brand_token") for c in all_of + any_of),
                "check_dom": any(c["type"] in ("dom_form_structure", "brand_mismatch", "dom_structural_hash", "exfil_endpoint", "title_keyword") for c in all_of + any_of),
                "check_attachments": any(c["type"].startswith("attachment") for c in all_of + any_of),
                "check_headers": any(c.get("scope") == "sender" or c["type"] == "reply_to_mismatch" for c in all_of + any_of),
            },
            "predicates": {"all_of": all_of, "any_of": any_of},
            "verdict": {
                "action": "BLOCK" if risk >= 0.70 else "REVIEW",
                "risk_score": round(risk, 2),
                "confidence": "HIGH" if risk >= 0.85 else "MEDIUM"
            },
            "reason_codes": sorted(codes),
            "fingerprints": dict(state.fingerprints),
            "source_incident": state.incident_id,
            "validation_metrics": {}  # filled in by ZeroFPRGuard
        }
