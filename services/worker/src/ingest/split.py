"""
Leakage-free split of the customer corpus into a development part (used to tune extractors and weights)
and a held-out test part (used only for the final metrics), ТЗ п. 4.1.3.3 / 7.3.

Objects are split by group, never individually, so one phishing kit / campaign never ends up on both sides:
* keis2 e-mails      — group = target brand folder;
* HTML attachments   — group = tag-skeleton hash of the page (same DOM template = same group);
* image lures        — group = the customer's cluster folder (``noise`` images are their own groups).

Objects already inspected during development (``seen``) force their whole group into the dev part.
The assignment is deterministic (sha256 of the group key) and saved as a manifest for reproducibility.
"""
import datetime
import hashlib
import json
import os
import re
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

try:
    from .dataset import iter_brand_samples
except (ImportError, ValueError):
    from ingest.dataset import iter_brand_samples

SPLIT_VERSION = "1"
_TAG = re.compile(rb"<\s*([a-zA-Z][a-zA-Z0-9]*)")


def html_skeleton_key(path: str, max_tags: int = 600) -> str:
    """Cheap DOM-template key: the sequence of opening tag names (no text, no attributes)."""
    try:
        with open(path, "rb") as f:
            data = f.read(2_000_000)
    except OSError:
        return "unreadable:" + os.path.basename(path)
    tags = b",".join(m.group(1).lower() for m in _TAG.finditer(data))
    tags = b",".join(tags.split(b",")[:max_tags])
    return "dom:" + hashlib.sha256(tags).hexdigest()[:16] if tags else "notags:" + os.path.basename(path)


def corpus_objects(dataset_root: str) -> Iterator[Tuple[str, str, str]]:
    """Yields (source, object path relative to dataset_root, group key) for the whole customer corpus."""
    keis2 = os.path.join(dataset_root, "keis2")
    if os.path.isdir(keis2):
        for brand, sample_dir in iter_brand_samples(keis2):
            yield "keis2", os.path.relpath(sample_dir, dataset_root), "brand:" + brand
    html_dir = os.path.join(dataset_root, "html_phishing2026")
    if os.path.isdir(html_dir):
        for name in sorted(os.listdir(html_dir)):
            if name.lower().endswith((".html", ".htm")):
                path = os.path.join(html_dir, name)
                yield "html", os.path.relpath(path, dataset_root), html_skeleton_key(path)
    png_dir = os.path.join(dataset_root, "grouped_png_phishing2026")
    if os.path.isdir(png_dir):
        for cluster in sorted(os.listdir(png_dir)):
            cdir = os.path.join(png_dir, cluster)
            if not os.path.isdir(cdir):
                continue
            for name in sorted(os.listdir(cdir)):
                rel = os.path.relpath(os.path.join(cdir, name), dataset_root)
                yield "png", rel, ("file:" + name) if cluster == "noise" else "cluster:" + cluster


def _bucket(key: str) -> float:
    return int(hashlib.sha256(key.encode("utf-8")).hexdigest()[:8], 16) / 0xFFFFFFFF


def _norm(path: str) -> str:
    return path.replace("\\", "/")


def build_split(dataset_root: str, dev_share: float = 0.3, seen: Iterable[str] = ()) -> Dict:
    seen = {_norm(s) for s in seen}
    for path in list(seen):  # a file inside a sample directory marks the directory as seen
        parts = path.split("/")
        seen.update("/".join(parts[:i]) for i in range(1, len(parts)))
    objects = list(corpus_objects(dataset_root))
    forced = {(src, g) for src, rel, g in objects if _norm(rel) in seen}
    assignment: Dict[str, str] = {}
    stats: Dict[str, Dict[str, int]] = {}
    for src, rel, group in objects:
        part = "dev" if (src, group) in forced or _bucket(f"{src}|{group}") < dev_share else "test"
        assignment[_norm(rel)] = part
        s = stats.setdefault(src, {"dev": 0, "test": 0, "dev_groups": 0, "test_groups": 0})
        s[part] += 1
    for part in ("dev", "test"):
        for src in stats:
            stats[src][f"{part}_groups"] = len({g for s, rel, g in objects
                                                if s == src and assignment[_norm(rel)] == part})
    return {
        "version": SPLIT_VERSION,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "dev_share": dev_share,
        "grouping": {"keis2": "brand folder", "html": "tag-skeleton hash", "png": "cluster folder (noise: per file)"},
        "forced_dev_objects": len(seen),
        "stats": stats,
        "objects": assignment,
    }


def save_split(split: Dict, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(split, f, ensure_ascii=False, indent=1)


def load_split(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def in_part(split: Optional[Dict], dataset_root: str, path: str, part: Optional[str]) -> bool:
    if not split or not part:
        return True
    return split["objects"].get(_norm(os.path.relpath(path, dataset_root))) == part


def sample_order(paths: List[str]) -> List[str]:
    """Deterministic pseudo-random order, so a --limit sample is spread over groups, not the first folders."""
    return sorted(paths, key=lambda p: hashlib.sha256(os.path.basename(os.path.normpath(p)).encode("utf-8")).hexdigest())
