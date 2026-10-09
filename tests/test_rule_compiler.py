import sys
import os
import json
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT_DIR, "services", "worker", "src"))

from rules.compiler import LSignatureCompiler
from rules.yara_gen import YARAGenerator

def test_l_signature_schema_compliance():
    compiler = LSignatureCompiler()
    rule = compiler.compile(
        target_brand="Госуслуги",
        risk_score=0.92,
        reason_codes=["BRAND_IMPERSONATION_CONFIRMED", "FORM_EXTERNAL_ACTION"],
        final_url="https://gosuslugi-fake.ru/oauth/authorize.php",
        has_password=True,
        has_external_action=True,
        allowed_domains=["gosuslugi.ru"]
    )

    assert rule["$schema"] == "https://drweb.com/schemas/lar-rule-v1.json"
    assert rule["rule_id"].startswith("LAR-2026-")
    assert rule["target_brand"] == "Госуслуги"
    assert rule["verdict"]["action"] == "BLOCK"
    assert rule["validation_metrics"]["zero_fpr_verified"] is True
    assert rule["validation_metrics"]["false_positives_count"] == 0

def test_yara_generator():
    yara_gen = YARAGenerator()
    
    # Telegram rule
    tg_rule = yara_gen.generate(["RC_ATTACH_TELEGRAM_EXFIL"], brand_name="Сбер")
    assert tg_rule is not None
    assert "api.telegram.org/bot" in tg_rule
    assert "rule DrWeb_Phish_Telegram_Exfil_" in tg_rule

    # Discord rule
    dc_rule = yara_gen.generate(["RC_ATTACH_DISCORD_EXFIL"])
    assert dc_rule is not None
    assert "discord.com/api/webhooks" in dc_rule

    # Double extension rule
    ext_rule = yara_gen.generate(["RC_LURE_DOUBLE_EXTENSION"])
    assert ext_rule is not None
    assert "\\.pdf\\.png" in ext_rule
