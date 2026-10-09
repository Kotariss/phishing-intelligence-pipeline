"""Robustness scenarios (ТЗ табл. 11): domain/URL change, design change, delayed loading."""
from evaluation import _mutate_design, _mutate_delayed, _mutate_url
from helpers import run_page, run_file, BRAND_LOGIN_KIT
from helpers_demo import TELEGRAM_KIT

KIT = BRAND_LOGIN_KIT.format(title="Госуслуги — вход", h1="Вход на Госуслуги", path="esia", footer="")


def test_detection_survives_domain_and_url_change():
    for seed in range(3):
        assert run_page(_mutate_url("https://gosuslugi-vhod.online/esia/login", seed), KIT).verdict == "MALICIOUS"


def test_detection_survives_design_change():
    assert run_page("https://x-portal.top/login", _mutate_design(KIT, 7)).verdict == "MALICIOUS"
    assert run_file("invoice.html", _mutate_design(TELEGRAM_KIT, 3).encode("utf-8")).verdict == "MALICIOUS"


def test_detection_survives_delayed_loading():
    delayed = _mutate_delayed(TELEGRAM_KIT)
    assert "api.telegram.org" not in delayed  # nothing visible in the static HTML
    state = run_file("invoice.html", delayed.encode("utf-8"))
    assert state.verdict == "MALICIOUS"
    assert "RC_ATTACH_TELEGRAM_EXFIL" in state.reason_codes
