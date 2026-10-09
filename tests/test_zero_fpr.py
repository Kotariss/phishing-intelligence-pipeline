import sys
import os
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT_DIR, "services", "worker", "src"))

from rules.zero_fpr_guard import ZeroFPRGuard, BENIGN_BASELINE_CORPUS
from rules.compiler import LSignatureCompiler

def test_zero_fpr_level1_brand_allowlist():
    guard = ZeroFPRGuard()
    
    # Official domains must return True (is legitimate)
    assert guard.check_level1_brand_allowlist("Сбер", "https://online.sberbank.ru/auth") is True
    assert guard.check_level1_brand_allowlist("Госуслуги", "https://esia.gosuslugi.ru/login") is True
    assert guard.check_level1_brand_allowlist("Т-Банк", "https://www.tbank.ru") is True
    
    # Phishing domain must return False
    assert guard.check_level1_brand_allowlist("Сбер", "https://sber-hack.org") is False

def test_zero_fpr_benign_baseline_regression():
    compiler = LSignatureCompiler()
    guard = ZeroFPRGuard()

    # Create a rule targeting fake Sberbank
    rule = compiler.compile(
        target_brand="Сбер",
        risk_score=0.95,
        reason_codes=["BRAND_IMPERSONATION_CONFIRMED", "FORM_PASSWORD_HARVESTING"],
        final_url="https://sber-phish.net/login.php",
        has_password=True,
        has_external_action=True,
        allowed_domains=["sberbank.ru", "sber.ru"]
    )

    passed, fp_count, fp_details = guard.evaluate_rule_on_baseline(rule)
    assert passed is True, f"False Positives triggered: {fp_details}"
    assert fp_count == 0

def test_verify_blocks_fpr_violation():
    guard = ZeroFPRGuard()
    
    # Legitimate URL should be clamped to CLEAN
    approved, note, score = guard.verify(
        risk_score=0.85,
        target_brand="Сбер",
        target_url="https://online.sberbank.ru/auth"
    )
    assert approved is True
    assert score < 0.30  # Clamped to CLEAN
    assert "Level 1" in note
