import sys
import os
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT_DIR, "services", "worker", "src"))

from brands.matcher import get_brand_registry

def test_registry_contains_175_brands():
    reg = get_brand_registry()
    assert len(reg.brands) == 175, f"Expected 175 brands, got {len(reg.brands)}"

def test_russian_brand_lookups():
    reg = get_brand_registry()
    for name in ["Сбербанк", "Сбер", "Т-Банк", "Тинькофф", "ВТБ", "Госуслуги", "Ozon", "Wildberries"]:
        b = reg.find_brand(name)
        assert b is not None, f"Failed to find brand: {name}"

def test_allowlist_domain_matching():
    reg = get_brand_registry()
    
    # Sber legitimate vs fake
    assert reg.is_domain_allowed("sber", "https://online.sberbank.ru/auth") is True
    assert reg.is_domain_allowed("sber", "https://sberbank.ru") is True
    assert reg.is_domain_allowed("sber", "https://sber-secure-auth.xyz") is False

    # Gosuslugi legitimate vs fake
    assert reg.is_domain_allowed("gosuslugi", "https://esia.gosuslugi.ru/login") is True
    assert reg.is_domain_allowed("gosuslugi", "https://gosuslugi-pay-fine.ru") is False

def test_impersonation_detection():
    reg = get_brand_registry()
    impersonated, b, reason = reg.check_brand_impersonation("Сбер", "https://sber-phish.net/login.php")
    assert impersonated is True
    assert "does NOT match" in reason

    legit, b, reason = reg.check_brand_impersonation("Сбер", "https://online.sberbank.ru/index.html")
    assert legit is False
    assert "legitimate" in reason
