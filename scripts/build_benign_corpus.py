"""
Builds services/worker/src/rules/benign_corpus.json — feature records of known-legitimate objects
used by the Zero FPR Guard to regression-test every rule before it enters the artefact package.

    python scripts/build_benign_corpus.py
"""
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "services", "worker", "src"))
sys.path.insert(0, os.path.join(ROOT, "services", "sandbox", "src"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures"))

from attachment_parser import AttachmentParser  # noqa: E402
from rules.engine import build_record  # noqa: E402
import benign_samples  # noqa: E402

OUTPUT = os.path.join(ROOT, "services", "worker", "src", "rules", "benign_corpus.json")


def build() -> list:
    records = []
    for sample in benign_samples.HTML_PAGES:
        parsed = AttachmentParser.parse_html(sample["html"], base_url=sample["url"])
        rec = build_record(url=sample["url"], page=parsed, forms=parsed["forms"], dom_hash=parsed.get("dom_structural_hash"))
        rec.update({"id": sample["id"], "kind": "page"})
        records.append(rec)
    for sample in benign_samples.EMAILS:
        parsed = AttachmentParser.parse_eml(sample["eml"])
        rec = build_record(attachment=parsed, forms=parsed.get("forms", []))
        rec.update({"id": sample["id"], "kind": "email"})
        records.append(rec)
    return records


def main():
    records = build()
    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=1)
    print(f"Wrote {len(records)} benign feature records to {os.path.relpath(OUTPUT, ROOT)}")


if __name__ == "__main__":
    main()
