import os
import json
import re
from typing import List, Dict, Optional, Tuple, Any
from urllib.parse import urlparse

# Aliases that are ordinary words (or too short) must match case-sensitively and never
# take part in domain look-alike detection: "line", "meta", "visa", "shell", "au", ...
COMMON_WORDS = {
    "line", "meta", "visa", "shell", "apple", "booking", "delta", "ledger", "pairs", "etc",
    "ana", "au", "wb", "vk", "rtl", "citi", "mcb", "web admin", "desk gear", "pony express", "costco",
}
# Second-level labels that are too generic to be a look-alike signal on their own.
LOOKALIKE_STOP = {"online", "account", "secure", "login", "mail", "bank", "card", "post", "cloud",
                  "support", "service", "team", "group", "store", "point", "money", "life", "express",
                  "delta", "shell", "apple", "line", "meta", "visa", "booking", "ledger", "pairs",
                  "outlook", "office", "teams", "drive", "share", "point", "store", "costco"}


_FULLWIDTH_LATIN = re.compile(r'[Ａ-Ｚａ-ｚ]')
_LATIN = re.compile(r'[A-Za-z]')
_LETTER_RUN = re.compile(r'[^\W\d_]+')
_HOMOGLYPH_MAP = str.maketrans("АВЕКМНОРСТХаеорсухіјѕΑΒΕΗΙΚΜΝΟΡΤΧΥΖο",
                               "ABEKMHOPCTXaeopcyxijsABEHIKMNOPTXYZo")
_HOMOGLYPH_CHARS = re.compile("[" + "АВЕКМНОРСТХаеорсухіјѕΑΒΕΗΙΚΜΝΟΡΤΧΥΖο" + "]")
_CJK = re.compile(r'[぀-ヿ㐀-鿿가-힯]')
_ZERO_WIDTH = re.compile(r'[­​-‏⁠-⁤﻿]')


def _unmask_letters(text: str) -> Tuple[str, bool]:
    """Full-width Latin letters ('MOＮEX') and Cyrillic / Greek look-alikes inside Latin words ('МONEX')."""
    changed = False
    if _FULLWIDTH_LATIN.search(text):
        text = _FULLWIDTH_LATIN.sub(lambda m: chr(ord(m.group(0)) - 0xFEE0), text)
        changed = True

    def fix(m: re.Match) -> str:  # one run of letters: 'Яндекс.Go' is two runs, 'МONEX' is one
        nonlocal changed
        word = m.group(0)
        if _LATIN.search(word) and _HOMOGLYPH_CHARS.search(word):
            changed = True
            return word.translate(_HOMOGLYPH_MAP)
        return word
    return _LETTER_RUN.sub(fix, text), changed


def normalize_display_text(text: str) -> Tuple[str, bool]:
    """Removes obfuscation used to evade brand matching in sender names / titles:
    zero-width characters ('セ​ブ​ン'), letter spacing ('A m a z o n'), full-width Latin letters
    ('MOＮEX') and Cyrillic / Greek look-alike letters mixed into Latin words ('МONEX').
    Returns (normalized_text, was_obfuscated)."""
    if not text:
        return "", False
    cleaned = _ZERO_WIDTH.sub("", text).replace(" ", " ")
    obfuscated = cleaned != text.replace(" ", " ")
    cleaned, unmasked = _unmask_letters(cleaned)
    obfuscated = obfuscated or unmasked
    out: List[str] = []
    run: List[str] = []
    for tok in cleaned.split(" ") + [""]:
        if len(tok) == 1 and tok.isalnum():
            run.append(tok)
            continue
        if len(run) >= 3:  # 'A m a z o n.co.jp' -> 'Amazon.co.jp'
            obfuscated = True
            # the last spaced letter may be glued to a suffix: 'n.co.jp'
            glued = len(tok) > 1 and tok[0].isalnum() and not tok[1].isalnum()
            out.append("".join(run) + (tok if glued else ""))
            if tok and not glued:
                out.append(tok)
        else:
            out.extend(run)
            if tok:
                out.append(tok)
        run = []
    return " ".join(out), obfuscated


def alias_pattern(alias: str, flags: int = re.IGNORECASE) -> re.Pattern:
    """Whole-word match for alphabetic scripts; plain substring for CJK (no spaces between words).
    Boundaries only consider letters of the alias' own script class so that 'ANAマイレージ' matches 'ANA'."""
    escaped = re.escape(alias)
    if _CJK.search(alias):
        return re.compile(escaped, flags)
    if alias.isascii():
        return re.compile(rf'(?<![A-Za-z0-9_-]){escaped}(?![A-Za-z0-9_-])', flags)
    return re.compile(rf'(?<![\w-]){escaped}(?![\w-])', flags)


def extract_hostname(domain_or_url: str) -> str:
    if not domain_or_url:
        return ""
    value = domain_or_url.strip().lower()
    if "://" in value:
        try:
            return (urlparse(value).hostname or "").rstrip(".")
        except ValueError:
            return ""
    value = value.split("/")[0].split("@")[-1]
    return value.split(":")[0].rstrip(".")


class BrandRegistry:
    def __init__(self, registry_path: Optional[str] = None):
        if not registry_path:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            registry_path = os.path.join(current_dir, "brand_registry.json")

        self.registry_path = registry_path
        self.brands: List[Dict[str, Any]] = []
        self.by_id: Dict[str, Dict[str, Any]] = {}
        self.alias_map: Dict[str, str] = {}  # lower alias -> brand_id
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        self._text_patterns: List[Tuple[re.Pattern, str, str]] = []  # (pattern, brand_id, alias)
        self._lookalike_tokens: List[Tuple[str, str]] = []  # (token, brand_id)
        self.load()

    def load(self):
        if not os.path.exists(self.registry_path):
            raise FileNotFoundError(f"Brand registry file not found: {self.registry_path}")

        with open(self.registry_path, "r", encoding="utf-8") as f:
            self.brands = json.load(f)

        self.by_id.clear()
        self.alias_map.clear()
        self._compiled_patterns.clear()
        self._text_patterns.clear()
        self._lookalike_tokens.clear()

        lookalike = set()
        for b in self.brands:
            b_id = b["brand_id"]
            self.by_id[b_id] = b

            names = list(dict.fromkeys(list(b.get("aliases", [])) + [b["display_name"]]))
            for alias in names:
                self.alias_map[alias.lower().strip()] = b_id
            self.alias_map[b_id.lower().strip()] = b_id

            for alias in names:
                alias = alias.strip()
                low = alias.lower()
                if len(alias) < 2:
                    continue
                ambiguous = low in COMMON_WORDS or len(alias) <= 3
                flags = 0 if ambiguous else re.IGNORECASE
                self._text_patterns.append((alias_pattern(alias, flags), b_id, alias))

                token = re.sub(r'[^a-z0-9]', '', low)
                if len(token) >= 5 and low not in COMMON_WORDS and token not in LOOKALIKE_STOP:
                    lookalike.add((token, b_id))

            for dom in b.get("official_domains", []):
                label = dom.lower().split(".")[0] if dom.count(".") == 1 else dom.lower().split(".")[-2]
                if len(label) >= 5 and label not in LOOKALIKE_STOP and label not in COMMON_WORDS:
                    lookalike.add((label, b_id))

            compiled = []
            for pat in b.get("allowed_domain_patterns", []):
                try:
                    compiled.append(re.compile(pat, re.IGNORECASE))
                except re.error:
                    pass
            self._compiled_patterns[b_id] = compiled

        # Longest aliases first so that "Microsoft Outlook" wins over "Microsoft".
        self._text_patterns.sort(key=lambda t: len(t[2]), reverse=True)
        self._lookalike_tokens = sorted(lookalike, key=lambda t: len(t[0]), reverse=True)

    # ------------------------------------------------------------------ lookup
    def find_brand(self, query: str) -> Optional[Dict[str, Any]]:
        """Resolves a brand name (e.g. a VLM answer or a display name): exact alias first,
        then the longest alias occurring as a whole word inside the query."""
        if not query:
            return None
        q = query.lower().strip()
        if q in self.alias_map:
            return self.by_id[self.alias_map[q]]
        found = self.find_brand_in_text(query)
        return found[0] if found else None

    def find_brand_in_text(self, text: str) -> Optional[Tuple[Dict[str, Any], str]]:
        """Returns (brand, matched_alias) for the longest alias found as a whole word in text."""
        if not text:
            return None
        text, _ = normalize_display_text(text)
        for pattern, b_id, alias in self._text_patterns:
            if pattern.search(text):
                return self.by_id[b_id], alias
        return None

    def brand_keywords(self, brand_id: str) -> List[str]:
        b = self.by_id.get(brand_id) or {}
        names = list(dict.fromkeys(list(b.get("aliases", [])) + [b.get("display_name", "")]))
        return [n for n in names if n and len(n) >= 3]

    def is_domain_allowed(self, brand_id: str, domain_or_url: str) -> bool:
        """Checks if domain belongs to the official allowlist of the brand."""
        hostname = extract_hostname(domain_or_url)
        if not hostname:
            return False

        for pat in self._compiled_patterns.get(brand_id, []):
            if pat.search(hostname):
                return True

        brand = self.by_id.get(brand_id)
        if brand:
            for off_dom in brand.get("official_domains", []):
                off_dom_low = off_dom.lower()
                if hostname == off_dom_low or hostname.endswith("." + off_dom_low):
                    return True
        return False

    def find_brand_for_domain(self, domain_or_url: str) -> Optional[Dict[str, Any]]:
        """Finds if a domain/URL legitimately belongs to any brand in the registry."""
        hostname = extract_hostname(domain_or_url)
        if not hostname:
            return None
        for b in self.brands:
            if self.is_domain_allowed(b["brand_id"], hostname):
                return b
        return None

    def find_lookalike_brand(self, domain_or_url: str) -> Optional[Tuple[Dict[str, Any], str]]:
        """Brand name embedded in a host that is NOT an official domain of that brand,
        e.g. sberbank-online-secure.top, gosuslugi.help-center.ru. Returns (brand, token)."""
        hostname = extract_hostname(domain_or_url)
        if not hostname or re.match(r'^[\d.]+$', hostname):
            return None
        labels = hostname.split(".")
        searchable = ".".join(labels[:-1]) if len(labels) > 1 else hostname
        squashed = re.sub(r'[^a-z0-9.]', '', searchable)
        for token, b_id in self._lookalike_tokens:
            if token in squashed:
                if self.is_domain_allowed(b_id, hostname) or self.find_brand_for_domain(hostname):
                    return None
                return self.by_id[b_id], token
        return None

    def check_brand_impersonation(
        self,
        suspected_brand_name: str,
        target_url: str
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """
        Returns:
            (is_impersonation, brand_entry, reason)
        """
        brand = self.find_brand(suspected_brand_name)
        if not brand:
            return False, None, "Brand not recognized in registry"

        if self.is_domain_allowed(brand["brand_id"], target_url):
            return False, brand, f"Domain is legitimate for brand {brand['display_name']}"

        return True, brand, f"Domain does NOT match official allowlist for {brand['display_name']}"

# Global singleton
_default_matcher: Optional[BrandRegistry] = None

def get_brand_registry() -> BrandRegistry:
    global _default_matcher
    if _default_matcher is None:
        _default_matcher = BrandRegistry()
    return _default_matcher
