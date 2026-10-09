"""
Generates the comprehensive 175-brand registry for Phishing Intelligence Pipeline.
Maps all brands from file_for_case/keis2 with normalized IDs, aliases, and official domain regexes.
"""

import os
import json
import re

BRAND_DOMAINS_MAP = {
    # Russian Brands
    "Сбер": {
        "id": "sber",
        "display_name": "Сбер",
        "category": "banking_ru",
        "aliases": ["Сбербанк", "Сбер", "Sber", "Sberbank", "СберБизнес", "СберОнлайн"],
        "domains": ["sberbank.ru", "sber.ru", "online.sberbank.ru", "sberbank.com"]
    },
    "Т-Банк": {
        "id": "tbank",
        "display_name": "Т-Банк",
        "category": "banking_ru",
        "aliases": ["Т-Банк", "Тинькофф", "T-Bank", "Tinkoff", "ТБанк"],
        "domains": ["tbank.ru", "tinkoff.ru", "id.tbank.ru"]
    },
    "ВТБ": {
        "id": "vtb",
        "display_name": "ВТБ",
        "category": "banking_ru",
        "aliases": ["ВТБ", "VTB", "Банк ВТБ", "ВТБ Онлайн"],
        "domains": ["vtb.ru", "online.vtb.ru", "vtb24.ru"]
    },
    "Госуслуги": {
        "id": "gosuslugi",
        "display_name": "Госуслуги",
        "category": "gov_ru",
        "aliases": ["Госуслуги", "Gosuslugi", "ЕПГУ", "ЕСИА"],
        "domains": ["gosuslugi.ru", "esia.gosuslugi.ru"]
    },
    "Moc ру": {
        "id": "mos_ru",
        "display_name": "Мос.ру",
        "category": "gov_ru",
        "aliases": ["Мос.ру", "Mos.ru", "Портал Мэра Москвы"],
        "domains": ["mos.ru"]
    },
    "МФЦ": {
        "id": "mfc",
        "display_name": "МФЦ Мои Документы",
        "category": "gov_ru",
        "aliases": ["МФЦ", "Мои Документы", "MFC"],
        "domains": ["mfc.ru", "моидокументы.рф", "md.mos.ru"]
    },
    "Минцифры": {
        "id": "mintsifry",
        "display_name": "Минцифры России",
        "category": "gov_ru",
        "aliases": ["Минцифры", "Министерство цифрового развития", "Digital Gov"],
        "domains": ["digital.gov.ru"]
    },
    "М.Видео": {
        "id": "mvideo",
        "display_name": "М.Видео",
        "category": "marketplace_ru",
        "aliases": ["М.Видео", "МВидео", "M.Video", "Mvideo"],
        "domains": ["mvideo.ru"]
    },
    "Государственные лотереи": {
        "id": "stoloto",
        "display_name": "Столото (Государственные лотереи)",
        "category": "services_ru",
        "aliases": ["Столото", "Stoloto", "Государственные лотереи"],
        "domains": ["stoloto.ru"]
    },
    "Ozon": {
        "id": "ozon",
        "display_name": "Ozon",
        "category": "marketplace_ru",
        "aliases": ["Ozon", "Озон", "Ozon Банк"],
        "domains": ["ozon.ru", "finance.ozon.ru"]
    },
    "Wildberries": {
        "id": "wildberries",
        "display_name": "Wildberries",
        "category": "marketplace_ru",
        "aliases": ["Wildberries", "Вайлдберриз", "WB", "Вайлдберрис"],
        "domains": ["wildberries.ru", "wb.ru"]
    },
    "Mailru": {
        "id": "mailru",
        "display_name": "Mail.ru",
        "category": "tech_ru",
        "aliases": ["Mail.ru", "VK", "Почта Mail.ru"],
        "domains": ["mail.ru", "vk.company", "vk.com", "trk.mail.ru"]
    },
    "drweb": {
        "id": "drweb",
        "display_name": "Doctor Web",
        "category": "security",
        "aliases": ["Dr.Web", "Doctor Web", "Доктор Веб"],
        "domains": ["drweb.ru", "drweb.com"]
    },
    "Pony Express": {
        "id": "pony_express",
        "display_name": "Pony Express",
        "category": "logistics",
        "aliases": ["Pony Express", "Пони Экспресс"],
        "domains": ["ponyexpress.ru", "ponyexpress-logistics.com"]
    },

    # Global Tech, Cloud, Office
    "Microsoft Account Team": {
        "id": "microsoft_account",
        "display_name": "Microsoft Account",
        "category": "cloud_global",
        "aliases": ["Microsoft", "Microsoft 365", "Office 365", "MS Account"],
        "domains": ["microsoft.com", "office.com", "live.com", "microsoftonline.com", "login.microsoftonline.com"]
    },
    "Microsoft HR": {
        "id": "microsoft_hr",
        "display_name": "Microsoft HR",
        "category": "cloud_global",
        "aliases": ["Microsoft HR", "MS HR"],
        "domains": ["microsoft.com", "office.com"]
    },
    "Microsoft OneDrive": {
        "id": "microsoft_onedrive",
        "display_name": "Microsoft OneDrive",
        "category": "cloud_global",
        "aliases": ["OneDrive", "MS OneDrive", "Microsoft OneDrive"],
        "domains": ["onedrive.live.com", "microsoft.com", "sharepoint.com"]
    },
    "Microsoft Outlook": {
        "id": "microsoft_outlook",
        "display_name": "Microsoft Outlook",
        "category": "cloud_global",
        "aliases": ["Outlook", "Outlook 365", "MS Outlook"],
        "domains": ["outlook.com", "office.com", "microsoft.com", "outlook.office365.com"]
    },
    "SharePoint": {
        "id": "sharepoint",
        "display_name": "SharePoint",
        "category": "cloud_global",
        "aliases": ["SharePoint", "MS SharePoint"],
        "domains": ["sharepoint.com", "microsoft.com"]
    },
    "ShareFile": {
        "id": "sharefile",
        "display_name": "Citrix ShareFile",
        "category": "cloud_global",
        "aliases": ["ShareFile", "Citrix ShareFile"],
        "domains": ["sharefile.com", "citrix.com"]
    },
    "Apple ID": {
        "id": "apple_id",
        "display_name": "Apple ID",
        "category": "tech_global",
        "aliases": ["Apple", "Apple ID", "Apple Account"],
        "domains": ["apple.com", "appleid.apple.com", "icloud.com"]
    },
    "Apple AppStore": {
        "id": "apple_appstore",
        "display_name": "Apple App Store",
        "category": "tech_global",
        "aliases": ["App Store", "Apple AppStore"],
        "domains": ["apple.com", "itunes.apple.com"]
    },
    "Apple Support Team": {
        "id": "apple_support",
        "display_name": "Apple Support",
        "category": "tech_global",
        "aliases": ["Apple Support", "Apple Care"],
        "domains": ["apple.com", "support.apple.com"]
    },
    "Apple iCloud": {
        "id": "apple_icloud",
        "display_name": "Apple iCloud",
        "category": "tech_global",
        "aliases": ["iCloud", "Apple iCloud"],
        "domains": ["icloud.com", "apple.com"]
    },
    "Adobe": {
        "id": "adobe",
        "display_name": "Adobe",
        "category": "tech_global",
        "aliases": ["Adobe", "Adobe Sign", "Adobe Acrobat", "Creative Cloud"],
        "domains": ["adobe.com", "adobesign.com", "acrobat.adobe.com"]
    },
    "DocuSign": {
        "id": "docusign",
        "display_name": "DocuSign",
        "category": "b2b_global",
        "aliases": ["DocuSign", "Докьюсайн"],
        "domains": ["docusign.com", "docusign.net"]
    },
    "Dropbox": {
        "id": "dropbox",
        "display_name": "Dropbox",
        "category": "cloud_global",
        "aliases": ["Dropbox"],
        "domains": ["dropbox.com"]
    },
    "Google": {
        "id": "google",
        "display_name": "Google",
        "category": "tech_global",
        "aliases": ["Google", "Google Workspace", "Gmail", "Google Drive"],
        "domains": ["google.com", "gmail.com", "accounts.google.com"]
    },
    "OpenAI": {
        "id": "openai",
        "display_name": "OpenAI",
        "category": "tech_global",
        "aliases": ["OpenAI", "ChatGPT"],
        "domains": ["openai.com", "chatgpt.com"]
    },

    # Financial & Banks Global
    "PayPal": {
        "id": "paypal",
        "display_name": "PayPal",
        "category": "finance_global",
        "aliases": ["PayPal", "Пейпал"],
        "domains": ["paypal.com", "paypal.me"]
    },
    "Visa": {
        "id": "visa",
        "display_name": "Visa",
        "category": "finance_global",
        "aliases": ["Visa", "Визa"],
        "domains": ["visa.com", "visa.ru"]
    },
    "Mastercard": {
        "id": "mastercard",
        "display_name": "Mastercard",
        "category": "finance_global",
        "aliases": ["Mastercard", "Мастеркард"],
        "domains": ["mastercard.com", "mastercard.ru"]
    },
    "American Express": {
        "id": "amex",
        "display_name": "American Express",
        "category": "finance_global",
        "aliases": ["American Express", "Amex"],
        "domains": ["americanexpress.com", "aexp.com"]
    },
    "Bank of America": {
        "id": "bank_of_america",
        "display_name": "Bank of America",
        "category": "banking_us",
        "aliases": ["Bank of America", "BofA"],
        "domains": ["bankofamerica.com", "bofa.com"]
    },
    "Wells Fargo": {
        "id": "wells_fargo",
        "display_name": "Wells Fargo",
        "category": "banking_us",
        "aliases": ["Wells Fargo"],
        "domains": ["wellsfargo.com"]
    },
    "Citibank": {
        "id": "citibank",
        "display_name": "Citibank",
        "category": "banking_global",
        "aliases": ["Citibank", "Citi"],
        "domains": ["citibank.com", "citi.com"]
    },
    "Capital One": {
        "id": "capital_one",
        "display_name": "Capital One",
        "category": "banking_us",
        "aliases": ["Capital One"],
        "domains": ["capitalone.com"]
    },
    "Fidelity": {
        "id": "fidelity",
        "display_name": "Fidelity Investments",
        "category": "finance_us",
        "aliases": ["Fidelity"],
        "domains": ["fidelity.com"]
    },
    "BNP Paribas": {
        "id": "bnp_paribas",
        "display_name": "BNP Paribas",
        "category": "banking_eu",
        "aliases": ["BNP Paribas"],
        "domains": ["bnpparibas.com", "mabanque.bnpparibas"]
    },
    "Deutsche Bank": {
        "id": "deutsche_bank",
        "display_name": "Deutsche Bank",
        "category": "banking_eu",
        "aliases": ["Deutsche Bank"],
        "domains": ["db.com", "deutsche-bank.de"]
    },
    "HSBC Bank": {
        "id": "hsbc",
        "display_name": "HSBC Bank",
        "category": "banking_global",
        "aliases": ["HSBC", "HSBC Bank"],
        "domains": ["hsbc.com", "hsbc.co.uk"]
    },
    "Santander": {
        "id": "santander",
        "display_name": "Banco Santander",
        "category": "banking_eu",
        "aliases": ["Santander"],
        "domains": ["santander.com", "bancosantander.es"]
    },
    "QuickBooks": {
        "id": "quickbooks",
        "display_name": "Intuit QuickBooks",
        "category": "b2b_global",
        "aliases": ["QuickBooks", "Intuit"],
        "domains": ["quickbooks.intuit.com", "intuit.com"]
    },

    # Logistics Global
    "DHL": {
        "id": "dhl",
        "display_name": "DHL Express",
        "category": "logistics",
        "aliases": ["DHL", "DHL Express", "DHL Freight"],
        "domains": ["dhl.com", "dhl.de", "dhl-usa.com"]
    },
    "FedEx": {
        "id": "fedex",
        "display_name": "FedEx",
        "category": "logistics",
        "aliases": ["FedEx", "Federal Express"],
        "domains": ["fedex.com"]
    },
    "UPS": {
        "id": "ups",
        "display_name": "UPS",
        "category": "logistics",
        "aliases": ["UPS", "United Parcel Service"],
        "domains": ["ups.com"]
    },
    "DPD": {
        "id": "dpd",
        "display_name": "DPD Group",
        "category": "logistics",
        "aliases": ["DPD"],
        "domains": ["dpd.com", "dpd.ru", "dpd.de"]
    },
    "USPS": {
        "id": "usps",
        "display_name": "USPS",
        "category": "logistics_us",
        "aliases": ["USPS", "U.S. Postal Service"],
        "domains": ["usps.com"]
    },
    "PostNL": {
        "id": "postnl",
        "display_name": "PostNL",
        "category": "logistics_eu",
        "aliases": ["PostNL"],
        "domains": ["postnl.nl", "postnl.com"]
    },
    "La Poste": {
        "id": "la_poste",
        "display_name": "La Poste",
        "category": "logistics_eu",
        "aliases": ["La Poste", "Chronopost"],
        "domains": ["laposte.fr"]
    },

    # Crypto & Web3
    "MetaMask": {
        "id": "metamask",
        "display_name": "MetaMask",
        "category": "crypto",
        "aliases": ["MetaMask"],
        "domains": ["metamask.io"]
    },
    "Ledger": {
        "id": "ledger",
        "display_name": "Ledger",
        "category": "crypto",
        "aliases": ["Ledger"],
        "domains": ["ledger.com"]
    },
    "Trust Wallet": {
        "id": "trust_wallet",
        "display_name": "Trust Wallet",
        "category": "crypto",
        "aliases": ["Trust Wallet"],
        "domains": ["trustwallet.com"]
    },
    "Coinbase": {
        "id": "coinbase",
        "display_name": "Coinbase",
        "category": "crypto",
        "aliases": ["Coinbase"],
        "domains": ["coinbase.com"]
    },
}

def clean_brand_name(dirname: str) -> str:
    cleaned = re.sub(r'\(.*?\)', '', dirname).strip()
    return cleaned

def generate_registry(keis2_dir: str, output_file: str):
    dirs = sorted([d for d in os.listdir(keis2_dir) if os.path.isdir(os.path.join(keis2_dir, d))])
    
    registry = []
    seen_ids = set()

    for d in dirs:
        base_clean = clean_brand_name(d)
        
        # Check if mapped
        if d in BRAND_DOMAINS_MAP:
            info = BRAND_DOMAINS_MAP[d]
        elif base_clean in BRAND_DOMAINS_MAP:
            info = BRAND_DOMAINS_MAP[base_clean]
        else:
            # Fallback generator for Japanese/Global brand
            slug = re.sub(r'[^a-zA-Z0-9_]', '_', base_clean.lower()).strip('_')
            if not slug:
                slug = f"brand_{len(registry)+1}"
            
            # infer domain heuristic
            domain_guess = f"{slug.replace('_', '')}.com"
            if "japan" in d.lower() or "bank" in d.lower() and any(ord(c) > 127 for c in d):
                domain_guess = f"{slug.replace('_', '')}.co.jp"

            info = {
                "id": slug,
                "display_name": base_clean,
                "category": "general",
                "aliases": [base_clean, d],
                "domains": [domain_guess]
            }

        # Format regex patterns
        allowed_patterns = []
        for dom in info["domains"]:
            escaped = re.escape(dom)
            pattern = f"^([a-z0-9-]+\\.)*{escaped}$"
            allowed_patterns.append(pattern)

        brand_id = info["id"]
        counter = 1
        while brand_id in seen_ids:
            brand_id = f"{info['id']}_{counter}"
            counter += 1
        seen_ids.add(brand_id)

        entry = {
            "brand_id": brand_id,
            "raw_dir_name": d,
            "display_name": info["display_name"],
            "category": info.get("category", "general"),
            "aliases": sorted(list(set(info.get("aliases", [d, base_clean])))),
            "official_domains": info["domains"],
            "allowed_domain_patterns": allowed_patterns,
            "common_lures": ["login_page", "invoice", "payment", "security_alert"]
        }
        registry.append(entry)

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2, ensure_ascii=False)

    print(f"Generated brand registry with {len(registry)} brands saved to {output_file}")

if __name__ == "__main__":
    generate_registry("file_for_case/keis2", "services/worker/src/brands/brand_registry.json")
