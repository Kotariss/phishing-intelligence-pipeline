"""
Known-legitimate objects (ТЗ п. 4.1.2.3) used to (1) regression-test every generated rule before it
enters the artefact package and (2) measure false positives of the full pipeline.

The set deliberately contains hard negatives: login pages of target brands on their official
domains, brand mentions on third-party sites, payment logos on a merchant checkout, corporate SSO
posting credentials cross-domain, brand subsidiaries, marketing redirect chains, invoices with PDFs.
Pages are stored as offline snapshots (URL + HTML) — no network access is needed.
"""
import base64

LOGIN_FORM = """
<form action="{action}" method="post">
  <input type="text" name="login" placeholder="{login_ph}">
  <input type="password" name="password" placeholder="Пароль">
  <button type="submit">{button}</button>
</form>"""


def page(title, h1, body, form="", extra_head=""):
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title>
<link rel="icon" href="/favicon.ico">{extra_head}</head>
<body><header><h1>{h1}</h1></header><main>{body}{form}</main>
<footer><a href="/privacy">Политика конфиденциальности</a></footer></body></html>"""


HTML_PAGES = [
    {"id": "benign-sber-login", "url": "https://online.sberbank.ru/CSAFront/index.do",
     "html": page("СберБанк Онлайн — вход", "Вход в СберБанк Онлайн", "<p>Введите логин или идентификатор Сбера.</p>",
                  LOGIN_FORM.format(action="/CSAFront/authMain.do", login_ph="Логин", button="Войти"))},
    {"id": "benign-gosuslugi-login", "url": "https://esia.gosuslugi.ru/login/",
     "html": page("Госуслуги — вход", "Вход на Госуслуги", "<p>Телефон, почта или СНИЛС</p>",
                  LOGIN_FORM.format(action="/aas/oauth2/login", login_ph="Телефон / Email / СНИЛС", button="Войти"))},
    {"id": "benign-tbank-login", "url": "https://id.tbank.ru/auth/step?cid=web",
     "html": page("Т-Банк — вход в личный кабинет", "Вход в Т-Банк", "<p>Введите номер телефона</p>",
                  LOGIN_FORM.format(action="/auth/step", login_ph="Телефон", button="Продолжить"))},
    {"id": "benign-vtb-login", "url": "https://online.vtb.ru/login",
     "html": page("ВТБ Онлайн", "Вход в ВТБ Онлайн", "",
                  LOGIN_FORM.format(action="/login", login_ph="Логин", button="Войти"))},
    {"id": "benign-microsoft-login", "url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
     "html": page("Sign in to your account", "Microsoft", "<p>Sign in</p>",
                  LOGIN_FORM.format(action="https://login.live.com/ppsecure/post.srf", login_ph="Email, phone, or Skype", button="Sign in"))},
    {"id": "benign-paypal-login", "url": "https://www.paypal.com/signin",
     "html": page("Log in to your PayPal account", "PayPal", "",
                  LOGIN_FORM.format(action="/signin", login_ph="Email or mobile number", button="Log In"))},
    {"id": "benign-amazon-jp-login", "url": "https://www.amazon.co.jp/ap/signin",
     "html": page("Amazonサインイン", "サインイン", "",
                  LOGIN_FORM.format(action="https://www.amazon.co.jp/ap/signin", login_ph="Eメールまたは携帯番号", button="次に進む"))},
    {"id": "benign-sber-ast-login", "url": "https://www.sberbank-ast.ru/Login.aspx",
     "html": page("Сбербанк-АСТ — электронная торговая площадка", "Сбербанк-АСТ: вход для участников", "<p>Торговая площадка группы Сбер.</p>",
                  LOGIN_FORM.format(action="/Login.aspx", login_ph="Логин", button="Вход"))},
    {"id": "benign-banki-ru-login", "url": "https://www.banki.ru/profile/login/",
     "html": page("Банки.ру — вход в личный кабинет", "Вход в личный кабинет Банки.ру",
                  "<nav>Вклады · Кредиты · Ипотека · Рейтинги: Сбербанк, ВТБ, Т-Банк, Альфа-Банк</nav><p>Сравнивайте предложения банков.</p>",
                  LOGIN_FORM.format(action="/profile/login/", login_ph="Email", button="Войти"))},
    {"id": "benign-shop-checkout", "url": "https://shop.example-store.ru/checkout/payment",
     "html": page("Оформление заказа — Магазин бытовой техники", "Оплата заказа № 104233",
                  '<img src="/img/visa.svg" alt="Visa"><img src="/img/mc.svg" alt="Mastercard"><img src="/img/mir.svg" alt="МИР"><p>Оплата картой Visa, Mastercard или МИР. Платёж обрабатывает Сбербанк.</p>',
                  """<form action="https://securepay.tinkoff.ru/v2/Init" method="post">
                     <input name="cardnumber" autocomplete="cc-number" placeholder="Номер карты">
                     <input name="cvc" autocomplete="cc-csc" placeholder="CVC">
                     <button type="submit">Оплатить</button></form>""")},
    {"id": "benign-corp-sso", "url": "https://hr.romashka-corp.ru/login",
     "html": page("Кадровый портал ООО «Ромашка»", "Вход сотрудника",
                  "<p>Единый вход через корпоративный SSO.</p>",
                  LOGIN_FORM.format(action="https://sso.romashka-idp.com/auth/realms/corp/login-actions", login_ph="Табельный номер", button="Войти"))},
    {"id": "benign-intranet-login", "url": "https://portal.romashka-corp.ru/auth/login.php",
     "html": page("Портал — авторизация", "Авторизация", "",
                  LOGIN_FORM.format(action="/auth/login.php", login_ph="Логин", button="Войти"))},
    {"id": "benign-news-sber", "url": "https://www.rbc.ru/finances/09/10/2026/sber-rates",
     "html": page("Сбербанк повысил ставки по вкладам — РБК", "Сбербанк повысил ставки по вкладам",
                  "<p>Крупнейший банк страны объявил о повышении ставок. ВТБ и Т-Банк пока не меняли условия.</p>")},
    {"id": "benign-dhl-tracking", "url": "https://www.dhl.com/ru-ru/home/tracking.html?tracking-id=1461983596",
     "html": page("DHL — Отслеживание", "Отслеживание отправления", "<p>Статус: в пути.</p>")},
    {"id": "benign-russian-idn", "url": "https://xn--80aesfpebagmfblc0a.xn--p1ai/",
     "html": page("Стопкоронавирус.рф", "Официальная информация", "<p>Новости и рекомендации.</p>")},
    {"id": "benign-github-login", "url": "https://github.com/login",
     "html": page("Sign in to GitHub", "Sign in to GitHub", "",
                  LOGIN_FORM.format(action="/session", login_ph="Username or email address", button="Sign in"))},
    {"id": "benign-docusign-view", "url": "https://app.docusign.com/documents/details/7f2c",
     "html": page("DocuSign — Review Document", "Please review and sign", "<p>Agreement 2026-10.pdf</p>")},
    {"id": "benign-mvideo-promo", "url": "https://www.mvideo.ru/promo/sale-october",
     "html": page("Распродажа — М.Видео", "Октябрьская распродажа", '<p>Скидки до 50%.</p><script>window.location.hash="#top";</script>')},
]


def _eml(from_hdr, subject, html_body, reply_to=None, auth="spf=pass; dkim=pass; dmarc=pass", attachments=()):
    boundary = "==BOUNDARY_TEST=="
    headers = [
        f"From: {from_hdr}", "To: user@example.ru", f"Subject: {subject}",
        "Date: Thu, 08 Oct 2026 10:00:00 +0300", "MIME-Version: 1.0",
        f"Authentication-Results: mx.example.ru; {auth}",
        f'Content-Type: multipart/mixed; boundary="{boundary}"',
    ]
    if reply_to:
        headers.insert(1, f"Reply-To: {reply_to}")
    parts = [f"--{boundary}\nContent-Type: text/html; charset=utf-8\nContent-Transfer-Encoding: base64\n\n"
             + base64.encodebytes(html_body.encode("utf-8")).decode("ascii")]
    for name, ctype, payload in attachments:
        parts.append(f"--{boundary}\nContent-Type: {ctype}; name=\"{name}\"\nContent-Disposition: attachment; filename=\"{name}\"\n"
                     "Content-Transfer-Encoding: base64\n\n" + base64.encodebytes(payload).decode("ascii"))
    return ("\n".join(headers) + "\n\n" + "\n".join(parts) + f"\n--{boundary}--\n").encode("utf-8")


def _minimal_pdf(text: str) -> bytes:
    try:
        import pymupdf
        doc = pymupdf.open()
        doc.new_page().insert_text((72, 72), text)
        data = doc.tobytes()
        doc.close()
        return data
    except Exception:
        return b"%PDF-1.4\n% minimal\n" + text.encode("latin-1", "ignore") + b"\n%%EOF\n"


EMAILS = [
    {"id": "benign-mail-sber-newsletter",
     "eml": _eml("СберБанк <news@sberbank.ru>", "Новые условия по вкладам",
                 '<h1>СберБанк</h1><p>Узнайте о новых ставках.</p><a href="https://www.sberbank.ru/ru/person/contributions">Подробнее</a>')},
    {"id": "benign-mail-sber-insurance",
     "eml": _eml("Сбербанк Страхование <info@sberins.ru>", "Ваш полис продлён",
                 '<p>Полис продлён на год.</p><a href="https://www.sberins.ru/lk/">Личный кабинет</a>')},
    {"id": "benign-mail-gosuslugi",
     "eml": _eml("Госуслуги <no-reply@gosuslugi.ru>", "Заявление принято",
                 '<p>Ваше заявление принято ведомством.</p><a href="https://www.gosuslugi.ru/lk">Перейти в личный кабинет</a>')},
    {"id": "benign-mail-ozon-order",
     "eml": _eml("OZON <order@sender.ozon.ru>", "Заказ 12345-0001 доставлен",
                 '<p>Заказ можно забрать в пункте выдачи.</p><a href="https://www.ozon.ru/my/orderlist">Мои заказы</a>')},
    {"id": "benign-mail-mvideo-tracking",
     "eml": _eml("М.Видео <news@mail.mvideo.ru>", "Скидки октября",
                 '<p>Распродажа!</p><a href="https://click.mail.mvideo.ru/track?u=https%3A%2F%2Fwww.mvideo.ru%2Fpromo">Смотреть</a>'
                 '<a href="https://www.mvideo.ru/unsubscribe">Отписаться</a>')},
    {"id": "benign-mail-invoice-pdf",
     "eml": _eml("Бухгалтерия ООО «Партнёр» <buh@partner-company.ru>", "Счёт на оплату № 4821",
                 "<p>Добрый день! Счёт во вложении. Оплата по реквизитам в счёте.</p>",
                 attachments=[("Счет_4821.pdf", "application/pdf", _minimal_pdf("Invoice 4821. Total: 120000 RUB"))])},
    {"id": "benign-mail-colleague",
     "eml": _eml("Иван Петров <ivan.petrov@gmail.com>", "Re: оплата аренды",
                 "<p>Привет! Перевёл через Сбербанк Онлайн, проверь, пожалуйста.</p>")},
    {"id": "benign-mail-docusign",
     "eml": _eml("DocuSign <dse@docusign.net>", "Please DocuSign: Agreement 2026-10",
                 '<p>Romashka LLC sent you a document to review and sign.</p><a href="https://app.docusign.com/documents/details/7f2c">REVIEW DOCUMENT</a>')},
    {"id": "benign-mail-github",
     "eml": _eml("GitHub <noreply@github.com>", "[GitHub] A new SSH key was added",
                 '<p>A new public key was added to your account.</p><a href="https://github.com/settings/keys">Review keys</a>')},
    {"id": "benign-mail-microsoft-security",
     "eml": _eml("Microsoft account team <account-security-noreply@accountprotection.microsoft.com>", "Microsoft account security info was added",
                 '<p>The following security info was added.</p><a href="https://account.live.com/proofs/manage">Review</a>')},
]


def _text_image(lines, size=(900, 520)) -> bytes:
    """A plain legitimate image with text (rendered locally, no external files)."""
    import io
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.load_default(size=30)
    except TypeError:  # Pillow without FreeType default font
        font = ImageFont.load_default()
    y = 30
    for line in lines:
        draw.text((40, y), line, fill="black", font=font)
        y += 48
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


# Image attachments of legitimate mail: banners, receipts, scanned invoices, a how-to screenshot.
IMAGES = [
    {"id": "benign-img-sale-banner", "lines": ["SUMMER SALE", "-30% on all shoes", "Shop now in our stores", "Unsubscribe"]},
    {"id": "benign-img-receipt", "lines": ["Receipt #48213", "Cappuccino      2.50", "Croissant       1.80", "Total           4.30", "Thank you for your purchase!"]},
    {"id": "benign-img-invoice-scan", "lines": ["INVOICE No 2026-118", "Date: 12.09.2026", "Consulting services", "Amount due: 1200 EUR", "Payment by bank transfer"]},
    {"id": "benign-img-teams-invite", "lines": ["Microsoft Teams meeting", "Friday 15:00-16:00", "Join on your computer or mobile app", "Meeting ID: 312 456 789"]},
    {"id": "benign-img-ru-promo", "lines": ["Акция недели!", "Скидка 20% на всю технику", "Подробности на сайте магазина"]},
    {"id": "benign-img-howto-portal", "lines": ["How to open the HR portal", "1. Go to portal.company.local", "2. Enter your login and password", "3. Open Documents > Payslips"]},
]
for _img in IMAGES:
    _img["png"] = _text_image(_img["lines"])
