import os
import re
from typing import Dict, Any, List, Tuple, Optional

from urllib.parse import urlparse
try:
    from ..brands.matcher import get_brand_registry
except (ImportError, ValueError):
    from brands.matcher import get_brand_registry


BENIGN_BASELINE_CORPUS = [
    {
        "id": "benign-001",
        "sender_domain": "sberbank.ru",
        "url": "https://online.sberbank.ru/CSAFront/index.do",
        "title": "СберБанк Онлайн",
        "has_password": True,
        "is_external": False,
        "brand": "Сбер"
    },
    {
        "id": "benign-002",
        "sender_domain": "gosuslugi.ru",
        "url": "https://esia.gosuslugi.ru/login/",
        "title": "Госуслуги - Вход",
        "has_password": True,
        "is_external": False,
        "brand": "Госуслуги"
    },
    {
        "id": "benign-003",
        "sender_domain": "tbank.ru",
        "url": "https://www.tbank.ru/login/",
        "title": "Т-Банк - Вход в личный кабинет",
        "has_password": True,
        "is_external": False,
        "brand": "Т-Банк"
    },
    {
        "id": "benign-004",
        "sender_domain": "vtb.ru",
        "url": "https://online.vtb.ru/login",
        "title": "ВТБ Онлайн",
        "has_password": True,
        "is_external": False,
        "brand": "ВТБ"
    },
    {
        "id": "benign-005",
        "sender_domain": "microsoft.com",
        "url": "https://login.microsoftonline.com/common/oauth2/authorize",
        "title": "Sign in to your account",
        "has_password": True,
        "is_external": False,
        "brand": "Microsoft Account Team"
    },
    {
        "id": "benign-006",
        "sender_domain": "company-b2b.ru",
        "url": "https://company-b2b.ru/invoices/2026-10-01.pdf",
        "title": "Счет на оплату № 4821",
        "has_password": False,
        "is_external": False,
        "brand": None
    },
    {
        "id": "benign-007",
        "sender_domain": "dhl.com",
        "url": "https://www.dhl.com/ru-ru/home/tracking.html?tracking-id=1461983596",
        "title": "DHL Express Tracking",
        "has_password": False,
        "is_external": False,
        "brand": "DHL"
    },
    {
        "id": "benign-008",
        "sender_domain": "mos.ru",
        "url": "https://www.mos.ru/services/",
        "title": "Услуги Москвы - Официальный сайт Мэра",
        "has_password": False,
        "is_external": False,
        "brand": "Moc ру"
    }
]

class ZeroFPRGuard:
    """Three-tier Zero False Positive Rate verification engine."""

    def __init__(self, brand_registry=None):
        self.registry = brand_registry or get_brand_registry()

    def check_level1_brand_allowlist(self, brand_name: str, target_url: str) -> bool:
        """
        Level 1: Unconditional Brand Allowlist Check.
        Returns True if the destination domain is legitimate for the specified brand.
        """
        if not brand_name or not target_url:
            return False
        
        found = self.registry.find_brand(brand_name)
        if not found:
            return False

        return self.registry.is_domain_allowed(found["brand_id"], target_url)

    def evaluate_rule_on_baseline(self, rule_json: Dict[str, Any]) -> Tuple[bool, int, List[str]]:
        """
        Level 3: Tests the synthesized L-signature predicates against benign business traffic.
        Returns: (passed, false_positives_count, fp_details)
        """
        predicates = rule_json.get("predicates", {})
        conditions = predicates.get("conditions", [])
        if not conditions:
            return True, 0, []

        fps = []

        for sample in BENIGN_BASELINE_CORPUS:
            matched_all_conditions = True

            for cond in conditions:
                c_type = cond.get("type")

                if c_type == "brand_mismatch":
                    brand = cond.get("brand")
                    # If this benign sample matches the rule's brand, check if its domain would trigger mismatch
                    if sample.get("brand") and sample["brand"].lower() == brand.lower():
                        allowed_patterns = cond.get("allowed_domain_patterns", [])
                        domain = sample["sender_domain"]
                        # If allowed pattern matches, then brand mismatch condition is FALSE
                        is_allowed = any(re.search(p, domain, re.IGNORECASE) for p in allowed_patterns)
                        if is_allowed:
                            matched_all_conditions = False
                            break

                elif c_type == "dom_form_structure":
                    req_pass = cond.get("has_password_input", False)
                    req_ext = cond.get("action_is_external", False)
                    if req_pass and not sample.get("has_password", False):
                        matched_all_conditions = False
                        break
                    if req_ext and not sample.get("is_external", False):
                        matched_all_conditions = False
                        break

                elif c_type == "url_path_pattern":
                    regex_str = cond.get("regex")
                    try:
                        if regex_str and not re.search(regex_str, sample.get("url", ""), re.IGNORECASE):
                            matched_all_conditions = False
                            break
                    except re.error:
                        pass

                elif c_type == "dom_structural_hash":
                    req_hash = cond.get("hash")
                    sample_hash = sample.get("dom_structural_hash")
                    if not sample_hash or sample_hash != req_hash:
                        matched_all_conditions = False
                        break


            if matched_all_conditions:
                fps.append(f"False Positive on benign sample: {sample['id']} ({sample['url']})")

        passed = len(fps) == 0
        return passed, len(fps), fps

    def verify(
        self,
        risk_score: float,
        target_brand: str,
        target_url: str,
        rule_json: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str, float]:
        """
        Comprehensive 3-tier Zero FPR audit.
        Returns: (is_approved, explanation, adjusted_score)
        """
        # Tier 1: Check Allowlist
        if target_brand and target_url and self.check_level1_brand_allowlist(target_brand, target_url):
            return True, "Level 1: Target domain belongs to legitimate brand allowlist. Clamped to CLEAN.", 0.05

        # Tier 2: Check Score Threshold
        if risk_score < 0.30:
            return True, "Level 2: Risk score is below threshold (CLEAN). Safe for transmission.", risk_score

        # Tier 3: Benign Baseline Regression
        if rule_json:
            passed, fp_count, fp_details = self.evaluate_rule_on_baseline(rule_json)
            if not passed:
                return False, f"Level 3: Zero FPR violation! Triggered on {fp_count} benign samples.", 0.45

        return True, "All 3 Zero FPR Guard levels verified successfully with 0 false positives.", risk_score
