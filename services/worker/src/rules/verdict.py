"""Verdict from reason codes — one implementation for the synthesizer and for re-scoring stored reports.

risk = noisy-OR of the weights of the independent evidence (rules/reason_codes.py); thresholds 0.30 / 0.70;
* «phishing» needs indicators from two independent groups (ТЗ 4.1.4.6) — or an exact match with a confirmed indicator;
* the model's reading of the text alone is advisory (it never decides alone, ТЗ А.1.3)."""
from typing import Any, Dict, Iterable

try:
    from . import reason_codes as rc
except ImportError:
    from rules import reason_codes as rc


def decide(codes: Iterable[str], clean_t: float = 0.30, mal_t: float = 0.70) -> Dict[str, Any]:
    codes = list(codes)
    scored = list(codes)
    advisory = []
    if any(c in rc.MODEL_TEXT_CODES for c in scored) and not rc.independent_groups([c for c in scored if c not in rc.MODEL_TEXT_CODES]):
        advisory = [c for c in codes if c in rc.MODEL_TEXT_CODES]
        scored = [c for c in scored if c not in rc.MODEL_TEXT_CODES]
    risk = round(rc.combine(scored), 2)
    groups = rc.independent_groups(scored)
    ioc_match = "RC_KNOWN_IOC_MATCH" in codes
    capped = None
    if risk >= mal_t and len(groups) < 2 and not ioc_match:
        verdict, capped = "SUSPICIOUS", {"risk": risk, "independent_groups": sorted(groups)}
    elif risk >= mal_t:
        verdict = "MALICIOUS"
    elif risk >= clean_t:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"
    return {"verdict": verdict, "risk": risk, "advisory": advisory, "capped": capped, "groups": sorted(groups)}
