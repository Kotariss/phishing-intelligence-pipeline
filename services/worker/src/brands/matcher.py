import os
import json
import re
from typing import List, Dict, Optional, Tuple, Any
from urllib.parse import urlparse

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
        self.load()

    def load(self):
        if not os.path.exists(self.registry_path):
            raise FileNotFoundError(f"Brand registry file not found: {self.registry_path}")

        with open(self.registry_path, "r", encoding="utf-8") as f:
            self.brands = json.load(f)

        self.by_id.clear()
        self.alias_map.clear()
        self._compiled_patterns.clear()

        for b in self.brands:
            b_id = b["brand_id"]
            self.by_id[b_id] = b
            
            # Map aliases
            for alias in b.get("aliases", []):
                self.alias_map[alias.lower().strip()] = b_id
            self.alias_map[b["display_name"].lower().strip()] = b_id
            self.alias_map[b_id.lower().strip()] = b_id

            # Compile regex patterns
            compiled = []
            for pat in b.get("allowed_domain_patterns", []):
                try:
                    compiled.append(re.compile(pat, re.IGNORECASE))
                except re.error:
                    pass
            self._compiled_patterns[b_id] = compiled

    def find_brand(self, query: str) -> Optional[Dict[str, Any]]:
        """Finds brand by name, alias or substring."""
        if not query:
            return None
        q = query.lower().strip()

        # Exact alias match
        if q in self.alias_map:
            return self.by_id[self.alias_map[q]]

        # Substring search in aliases
        for alias, b_id in self.alias_map.items():
            if len(alias) >= 3 and (alias in q or q in alias):
                return self.by_id[b_id]

        return None

    def is_domain_allowed(self, brand_id: str, domain_or_url: str) -> bool:
        """Checks if domain belongs to the official allowlist of the brand."""
        if not domain_or_url:
            return False

        # Extract hostname if full URL is passed
        hostname = domain_or_url.strip().lower()
        if "://" in hostname:
            parsed = urlparse(hostname)
            hostname = parsed.hostname or ""
        elif "/" in hostname:
            hostname = hostname.split("/")[0]

        patterns = self._compiled_patterns.get(brand_id, [])
        for pat in patterns:
            if pat.search(hostname):
                return True

        # Fallback check against official_domains suffix
        brand = self.by_id.get(brand_id)
        if brand:
            for off_dom in brand.get("official_domains", []):
                off_dom_low = off_dom.lower()
                if hostname == off_dom_low or hostname.endswith("." + off_dom_low):
                    return True

        return False

    def find_brand_for_domain(self, domain_or_url: str) -> Optional[Dict[str, Any]]:
        """Finds if a domain/URL legitimately belongs to any brand in the registry."""
        if not domain_or_url:
            return None
        hostname = domain_or_url.strip().lower()
        if "://" in hostname:
            parsed = urlparse(hostname)
            hostname = parsed.hostname or ""
        elif "/" in hostname:
            hostname = hostname.split("/")[0]

        for b in self.brands:
            b_id = b["brand_id"]
            if self.is_domain_allowed(b_id, hostname):
                return b
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

        is_allowed = self.is_domain_allowed(brand["brand_id"], target_url)
        if is_allowed:
            return False, brand, f"Domain is legitimate for brand {brand['display_name']}"

        return True, brand, f"Domain does NOT match official allowlist for {brand['display_name']}"

# Global singleton
_default_matcher: Optional[BrandRegistry] = None

def get_brand_registry() -> BrandRegistry:
    global _default_matcher
    if _default_matcher is None:
        _default_matcher = BrandRegistry()
    return _default_matcher
