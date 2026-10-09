import json
import os
from typing import Any, Dict, List, Optional, Tuple

try:
    from ..brands.matcher import get_brand_registry
    from .engine import rule_matches
except (ImportError, ValueError):
    from brands.matcher import get_brand_registry
    from rules.engine import rule_matches


CORPUS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benign_corpus.json")


def load_benign_corpus(path: str = CORPUS_PATH) -> List[Dict[str, Any]]:
    """Feature records of legitimate business traffic (built by scripts/build_benign_corpus.py
    from tests/fixtures/benign). Every L-signature is regression-tested against all of them."""
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


BENIGN_BASELINE_CORPUS = load_benign_corpus()


class ZeroFPRGuard:
    """Three-tier Zero False Positive Rate verification engine.

    Level 1  brand allowlist: content shown on an official domain of the detected brand is legitimate.
    Level 2  score threshold: only BLOCK-level incidents may emit active signatures.
    Level 3  regression: the rule must match its own source sample and NONE of the benign corpus records.
    """

    def __init__(self, brand_registry=None, corpus: Optional[List[Dict[str, Any]]] = None):
        self.registry = brand_registry or get_brand_registry()
        self.corpus = corpus if corpus is not None else BENIGN_BASELINE_CORPUS

    def check_level1_brand_allowlist(self, brand_name: str, target_url: str) -> bool:
        """True if the destination domain is legitimate for the specified brand."""
        if not brand_name or not target_url:
            return False
        found = self.registry.find_brand(brand_name)
        if not found:
            return False
        return self.registry.is_domain_allowed(found["brand_id"], target_url)

    def evaluate_rule_on_baseline(self, rule_json: Dict[str, Any]) -> Tuple[bool, int, List[str]]:
        """Level 3: evaluates the L-signature on every benign record with the reference engine."""
        fps = [f"{rec.get('id', '?')} ({rec.get('url') or rec.get('sender_domain') or rec.get('description', '')})"
               for rec in self.corpus if rule_matches(rule_json, rec)]
        return len(fps) == 0, len(fps), fps

    def verify_rule(self, rule_json: Dict[str, Any], source_record: Dict[str, Any], risk_score: float,
                    malicious_threshold: float = 0.70) -> Dict[str, Any]:
        """Full audit of a candidate rule. Returns validation metrics (also stored in the rule)."""
        self_match = rule_matches(rule_json, source_record)
        passed, fp_count, fp_details = self.evaluate_rule_on_baseline(rule_json)
        approved = self_match and passed and risk_score >= malicious_threshold
        if not self_match:
            note = "Level 3: rule does not match its own source sample (not distillable)."
        elif not passed:
            note = f"Level 3: Zero FPR violation — rule fires on {fp_count} benign samples."
        elif risk_score < malicious_threshold:
            note = "Level 2: incident below BLOCK threshold — rule kept as draft for review."
        else:
            note = f"All Zero FPR levels passed: 0 false positives on {len(self.corpus)} benign samples, self-match OK."
        return {
            "approved": approved,
            "note": note,
            "self_match": self_match,
            "benign_samples_tested": len(self.corpus),
            "false_positives_count": fp_count,
            "false_positive_samples": fp_details[:10],
        }
