"""
Reason-code catalogue: the single source of truth for weights, categories and explanations.

Scoring model (see synthesizer): independent evidence is combined with a noisy-OR
    risk = 1 - prod(1 - w_i)
so weak indicators can never add up linearly to a BLOCK verdict, while two independent
strong indicators quickly do. "critical" codes are near-certain on their own.
"""
from typing import Dict, NamedTuple


class ReasonCode(NamedTuple):
    weight: float
    category: str      # network | dom | brand | email | attachment | campaign | combo | info
    severity: str      # info | low | medium | high | critical
    description: str   # RU, shown to SOC analysts


REASON_CODES: Dict[str, ReasonCode] = {
    # --- Network / URL -----------------------------------------------------------------------
    "RC_REDIRECT_MULTI_HOP": ReasonCode(0.10, "network", "low", "Цепочка из 2+ перенаправлений до финальной страницы"),
    "RC_REDIRECT_ABUSE_TRUSTED": ReasonCode(0.25, "network", "medium", "Перенаправление через доверенный сервис (OAuth/сокращатель/open redirect)"),
    "RC_REDIRECT_CROSS_DOMAIN_JS": ReasonCode(0.15, "network", "low", "Клиентский (JS/meta) редирект на другой домен"),
    "RC_DROP_SCREENCONNECT_RAT": ReasonCode(0.97, "network", "critical", "Загрузка средства удалённого доступа ScreenConnect"),
    "RC_DROP_EXECUTABLE_PAYLOAD": ReasonCode(0.60, "network", "high", "Ссылка ведёт на исполняемый файл / образ диска"),
    "RC_EPHEMERAL_HOST_DEAD": ReasonCode(0.05, "info", "info", "Хост недоступен / ошибка (эфемерная фишинговая инфраструктура)"),
    "URL_IP_HOST": ReasonCode(0.30, "network", "medium", "В URL вместо домена используется IP-адрес"),
    "URL_IPFS_LINK": ReasonCode(0.25, "network", "medium", "Ссылка ведёт на шлюз IPFS: децентрализованное размещение, которое хостер не может удалить"),
    "URL_FREE_HOSTING": ReasonCode(0.15, "network", "low", "Страница размещена на бесплатном хостинге / конструкторе / IPFS"),
    "BRAND_HOMOGRAPH_DOMAIN": ReasonCode(0.55, "brand", "high", "Домен-омограф (смешение алфавитов в IDN)"),
    "BRAND_LOOKALIKE_DOMAIN": ReasonCode(0.45, "brand", "medium", "Домен содержит имя бренда, но не принадлежит бренду"),
    # --- DOM / page -----------------------------------------------------------------------------
    "RC_ATTACH_PASSWORD_INPUT": ReasonCode(0.20, "dom", "low", "Страница/вложение содержит поле ввода пароля"),
    "FORM_CARD_HARVESTING": ReasonCode(0.15, "dom", "low", "Форма запрашивает данные банковской карты"),
    "FORM_EXTERNAL_ACTION": ReasonCode(0.25, "dom", "medium", "Форма отправляет данные на сторонний домен"),
    "FORM_PASSWORD_HARVESTING": ReasonCode(0.45, "dom", "high", "Пароль отправляется на сторонний домен / JS-эндпоинт"),
    "FORM_SUBMIT_BUTTON_LINK": ReasonCode(0.10, "dom", "low", "Кнопка отправки ведёт не туда, куда указывает action формы"),
    "DOM_PREFILLED_VICTIM_EMAIL": ReasonCode(0.40, "dom", "medium", "Форма заранее заполнена адресом жертвы (персонализированный kit)"),
    "RC_ATTACH_TELEGRAM_EXFIL": ReasonCode(0.95, "dom", "critical", "Эксфильтрация данных в Telegram Bot API"),
    "RC_ATTACH_DISCORD_EXFIL": ReasonCode(0.95, "dom", "critical", "Эксфильтрация данных в Discord Webhook"),
    "RC_ATTACH_OBFUSCATED_JS": ReasonCode(0.30, "dom", "medium", "Обфусцированный JavaScript (packer/fromCharCode/base64-блоб)"),
    "RC_SANDBOX_EVASION_CODE": ReasonCode(0.25, "dom", "medium", "Код противодействия анализу (navigator.webdriver, debugger)"),
    # --- Brand ----------------------------------------------------------------------------------
    "BRAND_IMPERSONATION_CONFIRMED": ReasonCode(0.55, "brand", "high", "Страница визуально/по заголовку имитирует бренд на чужом домене"),
    "BRAND_MENTION_OFF_DOMAIN": ReasonCode(0.10, "brand", "low", "Бренд упоминается в тексте вне официального домена"),
    "RC_BRAND_SPOOF_DISPLAYNAME": ReasonCode(0.55, "email", "high", "Отображаемое имя отправителя имитирует бренд, домен отправителя чужой"),
    "BRAND_VISUAL_LURE_MATCH": ReasonCode(0.10, "brand", "low", "Тип визуальной приманки соответствует бренду"),
    # --- E-mail ---------------------------------------------------------------------------------
    "EMAIL_REPLY_TO_MISMATCH": ReasonCode(0.20, "email", "low", "Reply-To ведёт на другой домен, чем From"),
    "EMAIL_AUTH_FAIL": ReasonCode(0.20, "email", "low", "SPF/DMARC проверка не пройдена"),
    "EMAIL_LINK_TEXT_MISMATCH": ReasonCode(0.35, "email", "medium", "Текст ссылки показывает один домен, а ведёт на другой"),
    "EMAIL_DISPLAYNAME_OBFUSCATED": ReasonCode(0.30, "email", "medium", "Имя отправителя замаскировано невидимыми символами или разрядкой букв"),
    "EMAIL_SUBJECT_BRAND_OFF_DOMAIN": ReasonCode(0.20, "email", "low", "Тема письма упоминает бренд, отправитель не принадлежит бренду"),
    "RC_CLOAKING_TO_OFFICIAL": ReasonCode(0.30, "network", "medium", "Ссылка со стороннего домена перенаправляет на официальный сайт бренда (клоакинг)"),
    "VISUAL_DOCUMENT_LURE": ReasonCode(0.35, "content", "medium", "VLM: изображение-вложение изображает приманку (счёт, накладная, платёж, вход)"),
    "IMAGE_CREDENTIAL_PROMPT": ReasonCode(0.35, "content", "medium", "Изображение-вложение изображает форму ввода пароля / входа в учётную запись (текст на изображении или VLM)"),
    "IMAGE_FAKE_DOCUMENT_VIEWER": ReasonCode(0.35, "content", "medium", "Изображение-вложение изображает «защищённый документ», доступ к которому требует ввести пароль (фальшивый просмотрщик)"),
    "CONTENT_ACCOUNT_THREAT": ReasonCode(0.35, "content", "medium", "Текст угрожает потерей доступа к почте / учётной записи (пароль «истекает», письма «задержаны», ящик «переполнен») — типовой предлог кражи учётных данных"),
    "CONTENT_VICTIM_ADDRESSED": ReasonCode(0.20, "content", "low", "Текст обращается к получателю по адресу его почтового ящика (массовая персонализация фишингового набора)"),
    "ATTACH_FAKE_HUMAN_CHECK": ReasonCode(0.45, "attachment", "high", "Вложенный файл изображает проверку «вы не робот» / CAPTCHA: настоящие проверки выдаёт сайт, а не файл во вложении"),
    "CONTENT_LLM_LURE": ReasonCode(0.45, "content", "medium", "LLM классифицировала текст как фишинговую/мошенническую приманку"),
    # --- Attachments ----------------------------------------------------------------------------
    "ATTACH_OFFLINE_FORM": ReasonCode(0.75, "attachment", "critical", "HTML-вложение с формой ввода пароля или данных карты: локальная страница сбора данных всегда передаёт их на сторонний ресурс (составной признак)"),
    "ATTACH_HTML_REDIRECTOR": ReasonCode(0.60, "attachment", "high", "HTML-вложение перенаправляет на внешний сайт (meta/JS)"),
    "ATTACH_QR_CODE_FOUND": ReasonCode(0.30, "attachment", "medium", "QR-код со ссылкой во вложении (quishing)"),
    "ATTACH_ACTIVE_MACRO_MARKER": ReasonCode(0.50, "attachment", "high", "Office-документ с VBA-макросами"),
    "ATTACH_REMOTE_TEMPLATE": ReasonCode(0.60, "attachment", "high", "Office-документ загружает удалённый шаблон/OLE-объект"),
    "ATTACH_PDF_ACTIVE_CONTENT": ReasonCode(0.40, "attachment", "medium", "PDF содержит JavaScript / Launch-действие"),
    "ATTACH_EXECUTABLE": ReasonCode(0.60, "attachment", "high", "Исполняемый файл во вложении/архиве"),
    "RC_LURE_DOUBLE_EXTENSION": ReasonCode(0.60, "attachment", "high", "Двойное расширение файла (.pdf.png и т.п.)"),
    "RC_CAMPAIGN_INVARIANT_MATCH": ReasonCode(0.50, "campaign", "high", "Совпадение с известным индикатором кампании (имя файла)"),
    # --- Composite (evidence synergy) ------------------------------------------------------------
    "COMBO_BRAND_CREDENTIAL_FORM": ReasonCode(0.85, "combo", "critical", "Имитация бренда + форма сбора учётных данных на чужом домене"),
    "COMBO_LOOKALIKE_CREDENTIAL_FORM": ReasonCode(0.80, "combo", "critical", "Домен-двойник бренда + форма сбора учётных данных"),
}

# Codes that must not be neutralised by the brand allowlist (they are harmful wherever they appear).
NON_CLAMPABLE = {
    "RC_ATTACH_TELEGRAM_EXFIL", "RC_ATTACH_DISCORD_EXFIL", "RC_DROP_SCREENCONNECT_RAT",
    "RC_DROP_EXECUTABLE_PAYLOAD", "ATTACH_OFFLINE_FORM", "ATTACH_EXECUTABLE", "ATTACH_HTML_REDIRECTOR",
    "RC_LURE_DOUBLE_EXTENSION", "ATTACH_ACTIVE_MACRO_MARKER", "ATTACH_REMOTE_TEMPLATE",
}

UNKNOWN_CODE = ReasonCode(0.10, "info", "low", "Неклассифицированный индикатор")


def get(code: str) -> ReasonCode:
    return REASON_CODES.get(code, UNKNOWN_CODE)


def combine(codes) -> float:
    """Noisy-OR combination of independent evidence weights."""
    remaining = 1.0
    for code in set(codes):
        remaining *= (1.0 - get(code).weight)
    return round(1.0 - remaining, 4)
