"""
Deterministic lure signals in the text of an e-mail / HTML attachment (works without an LLM):

* account-access threat — the typical credential-theft pretext of webmail kits: the password "expires",
  incoming messages are "on hold", the mailbox is "full", the account will be "suspended";
* fake human check      — a CAPTCHA / "verify you are human" screen inside an attached file;
* victim addressed by e-mail — the kit greets the recipient by their mailbox address
  ("Dear info@company.cz"), which bulk-personalised phishing does and genuine services rarely do.

Each signal is a single medium-weight indicator: alone it can give at most "suspicious".
"""
import re
from typing import Dict, List

ACCOUNT_THREAT = re.compile(
    r"password\s+(?:is\s+|will\s+|has\s+)?(?:set\s+to\s+)?(?:expir|due\b|be\s+expired)|"
    r"(?:authentication|credentials?|account|mailbox|e-?mail)\s+(?:will\s+)?(?:expires?|expired|expiring)|"
    r"(?:\d+\s+)?(?:new\s+|incoming\s+|pending\s+)?(?:messages?|e-?mails?)\s+(?:are\s+|were\s+|have\s+been\s+|has\s+been\s+)?"
    r"(?:put\s+)?(?:on\s+hold|held|pending|failed|blocked|quarantined|suspended|undelivered)|"
    r"incoming\s+(?:pending\s+)?messages|undelivered\s+(?:messages|mails?)|message\s+restriction|"
    r"mailbox\s+(?:is\s+)?(?:full|almost\s+full|quota|storage)|storage\s+(?:is\s+)?(?:full|exceeded)|"
    r"account\s+(?:has\s+been\s+|will\s+be\s+|is\s+)?(?:on\s+hold|suspended|deactivated|disabled|locked|terminated)|"
    r"keep\s+(?:your\s+|using\s+)?(?:the\s+)?(?:same|current|old)\s+password|"
    r"verify\s+your\s+(?:mailbox|e-?mail\s+account|account\s+ownership)|"
    r"(?:encrypted|secure)\s+(?:message|document)\s+(?:received|for\b)|"
    r"(?:is\s+)?logging\s+you\s+out|please\s+re-?\s?log\s?-?in|sign\s+in\s+to\s+update|session\s+(?:has\s+)?expired|"
    r"пароль\s+(?:истека|устаре|будет\s+сброш)|почтов\w+\s+ящик\s+(?:переполн|заблок)|"
    r"(?:учётн|учетн)\w+\s+запис\w+\s+(?:будет\s+)?(?:заблокир|отключ|приостанов)|"
    r"письма\s+(?:задержан|не\s+доставлен)|"
    r"(?:口座|アカウント|カード|取引|ご利用)\S{0,8}(?:停止|制限|凍結|ロック)|差押|お客(?:様|さま)情報\S{0,4}(?:確認|更新)|"
    r"本人確認\S{0,6}(?:お願い|手続|必要)|パスワード\S{0,4}(?:変更|再設定)\S{0,6}(?:お願い|必要)|不正アクセス\S{0,8}(?:検知|確認)|"
    r"passwort\s+(?:läuft|ist)\s+ab|postfach\s+(?:ist\s+)?voll|heslo\s+(?:vypr|brzy)|"
    r"mot\s+de\s+passe\s+(?:expire|va\s+expirer)|contraseña\s+(?:caduca|expira)", re.I)
FAKE_HUMAN_CHECK = re.compile(
    r"(?:verify|prove|confirm)\s+(?:that\s+)?you\s+are\s+(?:a\s+)?(?:human|not\s+a\s+(?:robot|bot))|"
    r"not\s+a\s+robot|solve\s+(?:the\s+)?captcha|captcha\s+to\s+(?:prove|continue|verify)|"
    r"подтвердите,?\s+что\s+вы\s+не\s+робот", re.I)
GREETING_EMAIL = re.compile(
    r"(?:dear|hello|hi|attention|уважаем\w*|здравствуйте|hallo|dobrý\s+den|bonjour|hola)[\s,:!]{0,4}"
    r"(?:user\s+|customer\s+)?([\w.+-]+@[\w-]+(?:\.[\w-]+)+)|"
    r"(?:for|для|to)\s+([\w.+-]+@[\w-]+(?:\.[\w-]+)+)\b|"
    r"^\W*([\w.+-]+@[\w-]+(?:\.[\w-]+)+)\s+(?:dear|mail|account|your)", re.I)


def _around(text: str, m: re.Match, width: int = 60) -> str:
    return text[max(0, m.start() - width): m.end() + width].strip()


def text_lure_signals(text: str) -> Dict[str, object]:
    """{'account_threat': [snippets], 'victim_address': 'mailbox' or None} for one lure text."""
    text = " ".join((text or "").split())
    threats: List[str] = []
    for m in ACCOUNT_THREAT.finditer(text):
        s = _around(text, m)
        if not any(s in t or t in s for t in threats):
            threats.append(s)
        if len(threats) >= 3:
            break
    g = GREETING_EMAIL.search(text[:600])
    victim = next((x for x in g.groups() if x), None) if g else None
    h = FAKE_HUMAN_CHECK.search(text)
    return {"account_threat": threats, "victim_address": victim,
            "victim_snippet": _around(text, g, 40) if g else None,
            "human_check": _around(text, h, 50) if h else None}
