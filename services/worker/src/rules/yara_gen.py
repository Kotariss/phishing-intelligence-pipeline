import os
import uuid
import datetime
from typing import List, Optional

class YARAGenerator:
    """Generates production-grade YARA rules for attachments, scripts and lures."""

    def __init__(self, exports_dir: Optional[str] = None):
        self.exports_dir = exports_dir or os.path.join(os.getcwd(), "exports", "yara")
        os.makedirs(self.exports_dir, exist_ok=True)

    def generate(
        self,
        reason_codes: List[str],
        brand_name: Optional[str] = None,
        risk_score: float = 0.95
    ) -> Optional[str]:
        rand_suffix = uuid.uuid4().hex[:6]
        date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")

        if "RC_ATTACH_TELEGRAM_EXFIL" in reason_codes:
            rule = f"""/* Phishing Intelligence Pipeline Generated Rule */
rule DrWeb_Phish_Telegram_Exfil_{rand_suffix} {{
    meta:
        description = "Detects phishing attachment exfiltrating credentials to Telegram Bot API"
        author = "Phishing Intelligence Pipeline"
        date = "{date_str}"
        risk_score = {risk_score:.2f}
        target_brand = "{brand_name or 'Generic'}"
    strings:
        $tg1 = "api.telegram.org/bot" ascii nocase
        $tg2 = "sendMessage" ascii nocase
        $pass = /type\\s*=\\s*["']password["']/ ascii nocase
    condition:
        $tg1 and ($tg2 or $pass)
}}
"""
        elif "RC_ATTACH_DISCORD_EXFIL" in reason_codes:
            rule = f"""/* Phishing Intelligence Pipeline Generated Rule */
rule DrWeb_Phish_Discord_Exfil_{rand_suffix} {{
    meta:
        description = "Detects phishing attachment exfiltrating credentials to Discord Webhook"
        author = "Phishing Intelligence Pipeline"
        date = "{date_str}"
        risk_score = {risk_score:.2f}
        target_brand = "{brand_name or 'Generic'}"
    strings:
        $dc1 = "discord.com/api/webhooks" ascii nocase
        $pass = /type\\s*=\\s*["']password["']/ ascii nocase
    condition:
        $dc1 and $pass
}}
"""
        elif "RC_DROP_SCREENCONNECT_RAT" in reason_codes:
            rule = f"""/* Phishing Intelligence Pipeline Generated Rule */
rule DrWeb_Phish_ScreenConnect_RAT_{rand_suffix} {{
    meta:
        description = "Detects lure dropping ConnectWise ScreenConnect RAT"
        author = "Phishing Intelligence Pipeline"
        date = "{date_str}"
        risk_score = 1.00
    strings:
        $sc1 = "ScreenConnect.ClientSetup.msi" ascii nocase
        $sc2 = "ScreenConnect.ClientSetup.exe" ascii nocase
        $sc3 = "screenconnect.com" ascii nocase
    condition:
        $sc1 or $sc2 or ($sc3 and ($sc1 or $sc2))
}}
"""
        elif "RC_LURE_DOUBLE_EXTENSION" in reason_codes:
            rule = f"""/* Phishing Intelligence Pipeline Generated Rule */
rule DrWeb_Phish_Double_Extension_{rand_suffix} {{
    meta:
        description = "Detects graphic lures masquarading as office documents via double extension deception"
        author = "Phishing Intelligence Pipeline"
        date = "{date_str}"
        risk_score = {risk_score:.2f}
    strings:
        $ext1 = /\\.pdf\\.png$/i
        $ext2 = /\\.pfd\\.png$/i
        $ext3 = /\\.xlsx?\\.png$/i
        $ext4 = /\\.docx?\\.png$/i
    condition:
        1 of them
}}
"""
        elif "RC_ATTACH_PASSWORD_INPUT" in reason_codes or "FORM_PASSWORD_HARVESTING" in reason_codes:
            rule = f"""/* Phishing Intelligence Pipeline Generated Rule */
rule DrWeb_Phish_Credential_Harvest_{rand_suffix} {{
    meta:
        description = "Detects offline HTML attachment containing password input field and external form action"
        author = "Phishing Intelligence Pipeline"
        date = "{date_str}"
        risk_score = {risk_score:.2f}
        target_brand = "{brand_name or 'Generic'}"
    strings:
        $pass = /type\\s*=\\s*["']password["']/ ascii nocase
        $form_post = /method\\s*=\\s*["']post["']/ ascii nocase
        $ep1 = "login.php" ascii nocase
        $ep2 = "post.php" ascii nocase
        $ep3 = "formSubmit.php" ascii nocase
    condition:
        $pass and ($form_post or 1 of ($ep*))
}}
"""
        elif "RC_ATTACH_OBFUSCATED_JS" in reason_codes:
            rule = f"""/* Phishing Intelligence Pipeline Generated Rule */
rule DrWeb_Phish_Obfuscated_JS_{rand_suffix} {{
    meta:
        description = "Detects obfuscated JavaScript packers, hex decoders, or eval wrappers in attachment"
        author = "Phishing Intelligence Pipeline"
        date = "{date_str}"
        risk_score = {risk_score:.2f}
        target_brand = "{brand_name or 'Generic'}"
    strings:
        $s1 = /fromCharCode\\s*\\(/ ascii nocase
        $s2 = /unescape\\s*\\(/ ascii nocase
        $s3 = /eval\\s*\\(\\s*function\\s*\\(p,a,c,k,e,r\\)/ ascii nocase
        $s4 = /\\\\x[0-9a-f]{{2}}\\\\x[0-9a-f]{{2}}\\\\x[0-9a-f]{{2}}/ ascii nocase
    condition:
        2 of them
}}
"""
        elif "BRAND_IMPERSONATION_CONFIRMED" in reason_codes or "RC_BRAND_SPOOF_DISPLAYNAME" in reason_codes:
            safe_bname = (brand_name or "Generic").replace('"', '\\"')
            rule = f"""/* Phishing Intelligence Pipeline Generated Rule */
rule DrWeb_Phish_Brand_Spoof_{rand_suffix} {{
    meta:
        description = "Detects email or HTML lure spoofing brand display identity"
        author = "Phishing Intelligence Pipeline"
        date = "{date_str}"
        risk_score = {risk_score:.2f}
        target_brand = "{safe_bname}"
    strings:
        $brand = "{safe_bname}" nocase
        $lure1 = "пароль" nocase
        $lure2 = "вход" nocase
        $lure3 = "личный кабинет" nocase
        $lure4 = "безопасность" nocase
        $lure5 = "подтверждение" nocase
    condition:
        $brand and (1 of ($lure*))
}}
"""
        else:
            return None

        # Save to export folder
        rule_name = f"drweb_rule_{rand_suffix}.yar"
        file_path = os.path.join(self.exports_dir, rule_name)
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(rule)
        except Exception:
            pass

        return rule
