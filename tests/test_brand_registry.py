import pytest

from brands.matcher import get_brand_registry, normalize_display_text


@pytest.fixture(scope="module")
def registry():
    return get_brand_registry()


def test_registry_size_and_russian_brands(registry):
    assert len(registry.brands) >= 175
    for brand_id in ("sber", "gosuslugi", "tbank", "vtb", "mos_ru"):
        assert brand_id in registry.by_id


def test_official_domains_are_real_not_guessed(registry):
    # The old generator invented "<slug>.com" domains (an allowlist bypass for whoever registers them).
    assert registry.is_domain_allowed("japan_pension_service", "https://www.nenkin.go.jp/")
    assert not registry.is_domain_allowed("japan_pension_service", "japanpensionservice.co.jp")
    assert registry.is_domain_allowed("irs", "www.irs.gov") and not registry.is_domain_allowed("irs", "irs.com")


def test_domain_allowlist(registry):
    assert registry.is_domain_allowed("sber", "https://online.sberbank.ru/CSAFront/index.do")
    assert registry.is_domain_allowed("sber", "sberbank-ast.ru")  # group company (brand relations)
    assert not registry.is_domain_allowed("sber", "https://sberbank.ru.secure-login.top/")
    assert not registry.is_domain_allowed("sber", "https://online-sberbank-ru.xyz/")


def test_brand_resolution_prefers_whole_words(registry):
    assert registry.find_brand("Microsoft Outlook")["brand_id"] == "microsoft_outlook"
    assert registry.find_brand("Сбербанк")["brand_id"] == "sber"
    assert registry.find_brand_in_text("online banking with a land line") is None  # 'LINE' needs exact case
    assert registry.find_brand_in_text("Банки.ру — вход") is None


def test_cjk_and_obfuscated_display_names(registry):
    assert registry.find_brand_in_text("ANAマイレージクラブ・インフォメーション")[0]["brand_id"] == "ana"
    assert registry.find_brand_in_text("A m a z o n.co.jp")[0]["brand_id"] == "amazon"
    zw = "セ​ブ​ン​-​イ​レ​ブ​ン"
    assert registry.find_brand_in_text(zw)[0]["brand_id"] == "7_eleven"
    assert normalize_display_text(zw)[1] is True
    assert normalize_display_text("Иван Петров") == ("Иван Петров", False)


def test_lookalike_domains(registry):
    brand, token = registry.find_lookalike_brand("https://gosuslugi-pay.help-center.ru/x")
    assert brand["brand_id"] == "gosuslugi"
    assert registry.find_lookalike_brand("https://esia.gosuslugi.ru/") is None
    assert registry.find_lookalike_brand("https://pineapple-store.com/") is None  # 'apple' is a common word


def test_impersonation_check(registry):
    assert registry.check_brand_impersonation("Сбер", "https://sber-phish.net/login.php")[0] is True
    assert registry.check_brand_impersonation("Сбер", "https://www.sberbank.ru/")[0] is False
