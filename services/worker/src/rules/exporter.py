import json
import os
from typing import Optional

try:
    from ..config import get_settings
except (ImportError, ValueError):
    from config import get_settings


def export_artifacts(rule: Optional[dict], yara_rule: Optional[str], status: str,
                     exports_dir: Optional[str] = None) -> Optional[str]:
    """Writes verified rules to exports/{l_signatures,yara}; unverified drafts go to exports/drafts
    so they can never be shipped to the anti-spam engine by accident. Returns the JSON path."""
    if not rule:
        return None
    base = exports_dir or get_settings().EXPORTS_DIR
    active = status == "ACTIVE_VERIFIED"
    sig_dir = os.path.join(base, "l_signatures" if active else "drafts")
    os.makedirs(sig_dir, exist_ok=True)
    path = os.path.join(sig_dir, f"{rule['rule_id']}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rule, f, indent=2, ensure_ascii=False)
    if yara_rule:
        yara_dir = os.path.join(base, "yara" if active else "drafts")
        os.makedirs(yara_dir, exist_ok=True)
        with open(os.path.join(yara_dir, f"{rule['rule_id']}.yar"), "w", encoding="utf-8") as f:
            f.write(yara_rule)
    return path
