"""Reference site icons of the brands (ТЗ 4.1.2.1) and brand by an embedded icon (ТЗ 4.1.4.3)."""
import base64
import json
import os

from brands import icons as icons_mod
from brands.icons import ICONS_FILE, icon_from_data_uri, load_icons, match_icon
from helpers import run_page

HERE = os.path.join(os.path.dirname(__file__), "..", "services", "worker", "src", "brands")


def test_registry_has_reference_icons_for_most_brands():
    icons, max_d = load_icons()
    registry = json.load(open(os.path.join(HERE, "brand_registry.json"), encoding="utf-8"))
    assert len(icons) >= 100 and len(icons) <= len(registry) and max_d <= 6
    for brand_id, meta in list(icons.items())[:20]:
        assert os.path.isfile(os.path.join(HERE, "icons", f"{brand_id}.png")) and len(meta["dhash"]) == 16


def test_reference_icon_matches_its_own_brand_only_within_the_family():
    icons, _ = load_icons()
    brand_id = next(b for b in icons if len([x for x in icons if icons[x]["dhash"] == icons[b]["dhash"]]) == 1)
    with open(os.path.join(HERE, "icons", f"{brand_id}.png"), "rb") as f:
        b64 = base64.b64encode(f.read()).decode()
    hits = match_icon(b64)
    assert hits and hits[0][0] == brand_id and hits[0][1] == 0
    assert icon_from_data_uri("data:image/png;base64," + b64) == b64 and icon_from_data_uri("https://x/y.png") is None


def test_blank_image_matches_nothing():
    from PIL import Image
    import io
    buf = io.BytesIO()
    Image.new("RGB", (64, 64), (255, 255, 255)).save(buf, "PNG")
    assert match_icon(base64.b64encode(buf.getvalue()).decode()) == []


def test_page_with_a_brand_icon_inline_and_a_login_form_names_the_brand():
    icons, _ = load_icons()
    brand_id = next(b for b in icons if len([x for x in icons if icons[x]["dhash"] == icons[b]["dhash"]]) == 1)
    with open(os.path.join(HERE, "icons", f"{brand_id}.png"), "rb") as f:
        b64 = base64.b64encode(f.read()).decode()
    html = (f'<html><head><title>Sign in</title><link rel="icon" href="data:image/png;base64,{b64}"></head><body>'
            '<form action="https://collector-icon-test.top/p"><input type="password" name="p"></form></body></html>')
    state = run_page("https://login-icon-test.top/signin", html)
    assert state.brand_evidence.detected_brand_name and state.brand_evidence.detection_source == "brand_icon"
    assert "BRAND_IMPERSONATION_CONFIRMED" in state.reason_codes
