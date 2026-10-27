"""
Interpretable baseline classifier of phishing HTML pages (ТЗ 4.1.3.2–4.1.3.4, 4.1.5.2, 4.1.11).

A small CART decision tree (Gini, depth-limited) on RAW structural features of the page — counts and flags produced
by the HTML parser, not on reason codes and not on any model output. It is the reference the full pipeline is compared
with when the acceptance targets of table 3 are not reached (ТЗ 4.1.11, 8.4).

* training  — HTML attachments of the development part of the split (≤ ``GROUP_CAP`` pages per DOM template, so one kit
  does not dominate) against legitimate HTML: saved legitimate pages and HTML bodies of legitimate e-mails;
* evaluation — the held-out part of the split and held-out legitimate objects (never used for training);
* model file — JSON with the tree, feature names, feature importance, training data description and a content hash
  (model version). Pure Python: no extra dependencies.

    python phishctl.py baseline train [--out models/baseline_v1.json]
    python phishctl.py baseline eval  [--model models/baseline_v1.json] [--out reports/baseline_eval.json]
"""
import collections
import datetime
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SRC_DIR, "..", "..", ".."))
for _p in (SRC_DIR, os.path.join(REPO_ROOT, "services", "sandbox", "src"), os.path.join(REPO_ROOT, "tests", "fixtures")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

GROUP_CAP = 8          # pages per DOM template in the training set
MAX_DEPTH = 4
MIN_LEAF = 15
MODEL_VERSION_PREFIX = "baseline-tree"

FEATURES = [
    "forms_count", "has_password_field", "has_card_field", "external_action_forms", "hidden_fields",
    "links_count", "external_scripts", "external_resource_hosts", "iframes", "full_page_iframes",
    "has_telegram_exfil", "has_discord_exfil", "obfuscation_markers", "has_sandbox_evasion", "js_redirects",
    "has_meta_refresh", "link_text_mismatch", "js_endpoints", "js_external_endpoints", "title_length",
    "visible_text_length", "tags_count", "logo_image_hosts", "deobfuscated_layers",
]


def extract_features(parsed: Dict[str, Any]) -> Dict[str, float]:
    """Raw structural features of a parsed HTML page (`AttachmentParser.parse_html` result)."""
    forms = parsed.get("forms") or []

    def n(key):
        return float(len(parsed.get(key) or []))

    return {
        "forms_count": float(len(forms)),
        "has_password_field": float(bool(parsed.get("has_password_field"))),
        "has_card_field": float(any(f.get("has_card") for f in forms)),
        "external_action_forms": float(sum(1 for f in forms if f.get("is_external_target"))),
        "hidden_fields": n("hidden_fields"),
        "links_count": n("links"),
        "external_scripts": n("external_scripts"),
        "external_resource_hosts": n("external_resource_hosts"),
        "iframes": n("iframes"),
        "full_page_iframes": n("full_page_iframes"),
        "has_telegram_exfil": float(bool(parsed.get("has_telegram_exfil"))),
        "has_discord_exfil": float(bool(parsed.get("has_discord_exfil"))),
        "obfuscation_markers": n("obfuscation_markers"),
        "has_sandbox_evasion": float(bool(parsed.get("has_sandbox_evasion"))),
        "js_redirects": n("js_redirects"),
        "has_meta_refresh": float(bool(parsed.get("meta_refresh"))),
        "link_text_mismatch": n("link_text_mismatch"),
        "js_endpoints": n("js_endpoints"),
        "js_external_endpoints": n("js_external_endpoints"),
        "title_length": float(len(parsed.get("title") or "")),
        "visible_text_length": float(len(parsed.get("visible_text") or "")),
        "tags_count": float(parsed.get("tags_count") or 0),
        "logo_image_hosts": n("logo_image_hosts"),
        "deobfuscated_layers": float(parsed.get("deobfuscated_layers") or 0),
    }


def features_from_html(html: str, base_url: str = "") -> Dict[str, float]:
    from attachment_parser import AttachmentParser
    return extract_features(AttachmentParser.parse_html(html, base_url=base_url))


# ------------------------------------------------------------------------------------------------ the tree
def _gini(pos: float, neg: float) -> float:
    total = pos + neg
    if total <= 0:
        return 0.0
    p = pos / total
    return 2.0 * p * (1.0 - p)


class DecisionTree:
    """CART with class weights (balanced), binary splits ``feature <= threshold``."""

    def __init__(self, max_depth: int = MAX_DEPTH, min_leaf: int = MIN_LEAF):
        self.max_depth, self.min_leaf = max_depth, min_leaf
        self.nodes: List[Dict[str, Any]] = []
        self.importance: Dict[str, float] = collections.defaultdict(float)

    def fit(self, rows: List[List[float]], labels: List[int], names: List[str]) -> "DecisionTree":
        n_pos = sum(labels)
        n_neg = len(labels) - n_pos
        w_pos = len(labels) / (2.0 * n_pos) if n_pos else 1.0
        w_neg = len(labels) / (2.0 * n_neg) if n_neg else 1.0
        weights = [w_pos if y else w_neg for y in labels]
        self.names = names
        self.nodes = []
        self.importance = collections.defaultdict(float)
        self._grow(rows, labels, weights, list(range(len(rows))), 0, len(labels))
        total = sum(self.importance.values()) or 1.0
        self.importance = {k: round(v / total, 4) for k, v in sorted(self.importance.items(), key=lambda kv: -kv[1])}
        return self

    def _grow(self, rows, labels, weights, idx, depth, n_total) -> int:
        pos = sum(weights[i] for i in idx if labels[i])
        neg = sum(weights[i] for i in idx if not labels[i])
        node_id = len(self.nodes)
        node = {"id": node_id, "n": len(idx), "prob_phishing": round(pos / (pos + neg), 4) if pos + neg else 0.0}
        self.nodes.append(node)
        if depth >= self.max_depth or len(idx) < 2 * self.min_leaf or pos == 0 or neg == 0:
            return node_id
        best = None  # (gain, feature, threshold, left_idx, right_idx)
        parent = _gini(pos, neg) * (pos + neg)
        for f in range(len(self.names)):
            values = sorted({rows[i][f] for i in idx})
            if len(values) < 2:
                continue
            cands = [(a + b) / 2.0 for a, b in zip(values, values[1:])]
            if len(cands) > 24:  # quantile thresholds keep training fast on count features
                step = len(cands) / 24.0
                cands = [cands[int(k * step)] for k in range(24)]
            order = sorted(idx, key=lambda i: rows[i][f])
            for t in cands:
                lp = ln = 0.0
                cnt_l = 0
                for i in order:
                    if rows[i][f] > t:
                        break
                    cnt_l += 1
                    if labels[i]:
                        lp += weights[i]
                    else:
                        ln += weights[i]
                cnt_r = len(idx) - cnt_l
                if cnt_l < self.min_leaf or cnt_r < self.min_leaf:
                    continue
                rp, rn = pos - lp, neg - ln
                gain = parent - _gini(lp, ln) * (lp + ln) - _gini(rp, rn) * (rp + rn)
                if best is None or gain > best[0] + 1e-12:
                    best = (gain, f, t)
        if best is None or best[0] <= 1e-9:
            return node_id
        gain, f, t = best
        left = [i for i in idx if rows[i][f] <= t]
        right = [i for i in idx if rows[i][f] > t]
        self.importance[self.names[f]] += gain
        node.update(feature=self.names[f], threshold=round(t, 4))
        node["left"] = self._grow(rows, labels, weights, left, depth + 1, n_total)
        node["right"] = self._grow(rows, labels, weights, right, depth + 1, n_total)
        return node_id

    @staticmethod
    def predict_proba_nodes(nodes: List[Dict[str, Any]], features: Dict[str, float]) -> Tuple[float, List[str]]:
        """Probability of phishing and the decision path (human-readable conditions)."""
        node, path = nodes[0], []
        while "feature" in node:
            value = features.get(node["feature"], 0.0)
            go_left = value <= node["threshold"]
            path.append(f"{node['feature']} {'≤' if go_left else '>'} {node['threshold']} (значение {value:g})")
            node = nodes[node["left"] if go_left else node["right"]]
        return node["prob_phishing"], path


# ------------------------------------------------------------------------------------------------ data
def _legit_email_html(dataset_root: str) -> List[Tuple[str, str]]:
    """(id, html) of the HTML parts of the legitimate e-mails of the labelled set (`antiphishing_eml_540_combined`)."""
    import csv
    from attachment_parser import AttachmentParser
    root = os.path.join(dataset_root, "antiphishing_eml_540_combined")
    out = []
    manifest = os.path.join(root, "manifest.csv")
    if not os.path.isfile(manifest):
        return out
    with open(manifest, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("label") != "benign":
                continue
            path = os.path.join(root, row["evaluation_path"])
            try:
                with open(path, "rb") as fh:
                    parsed = AttachmentParser.parse_eml(fh.read())
            except Exception:
                continue
            if (parsed.get("body_html") or "").strip():
                out.append((row["id"], parsed["body_html"]))
    return out


def _bucket(key: str, parts: int = 10) -> int:
    return int(hashlib.sha256(key.encode()).hexdigest(), 16) % parts


def _phishing_html(dataset_root: str, split: Dict[str, Any], part: str) -> List[Tuple[str, str, str]]:
    """(path, group key, html) of the HTML attachments of the split part."""
    from ingest.split import html_skeleton_key
    out = []
    for rel, p in split["objects"].items():
        if p != part or not rel.startswith("html_phishing2026/"):
            continue
        path = os.path.join(dataset_root, rel)
        try:
            with open(path, "rb") as f:
                html = f.read(3_000_000).decode("utf-8", errors="ignore")
        except OSError:
            continue
        out.append((rel, html_skeleton_key(path), html))
    return out


def _legit_sets(dataset_root: str) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]]]:
    """Legitimate HTML split into (train, test): saved pages and e-mail bodies, 70 / 30 by a hash of the id."""
    import benign_samples
    items = [(s["id"], s["html"]) for s in benign_samples.HTML_PAGES] + _legit_email_html(dataset_root)
    train = [x for x in items if _bucket(x[0]) < 7]
    test = [x for x in items if _bucket(x[0]) >= 7]
    return train, test


def _matrix(htmls: List[str]) -> List[List[float]]:
    rows = []
    for html in htmls:
        f = features_from_html(html)
        rows.append([f[name] for name in FEATURES])
    return rows


# ------------------------------------------------------------------------------------------------ train / eval
def train(dataset_root: str, split_file: str, out_path: str) -> Dict[str, Any]:
    from ingest.split import load_split
    split = load_split(split_file)
    dev = _phishing_html(dataset_root, split, "dev")
    per_group: Dict[str, int] = collections.Counter()
    chosen = []
    for rel, group, html in dev:
        if per_group[group] < GROUP_CAP:
            per_group[group] += 1
            chosen.append((rel, group, html))
    legit_train, _ = _legit_sets(dataset_root)
    rows = _matrix([h for _, _, h in chosen]) + _matrix([h for _, h in legit_train])
    labels = [1] * len(chosen) + [0] * len(legit_train)
    tree = DecisionTree().fit(rows, labels, FEATURES)
    model = {
        "model": MODEL_VERSION_PREFIX, "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "algorithm": f"CART, Gini, balanced class weights, max_depth={MAX_DEPTH}, min_samples_leaf={MIN_LEAF}",
        "features": FEATURES, "decision_threshold": 0.5,
        "feature_importance": tree.importance, "tree": tree.nodes,
        "training": {"phishing_pages": len(chosen), "phishing_templates": len(per_group), "group_cap": GROUP_CAP,
                     "legitimate_objects": len(legit_train), "split_file": os.path.basename(split_file),
                     "split_part": "dev", "legitimate_source": "tests/fixtures/benign_samples.py pages + HTML of legitimate e-mails (70 %)"},
    }
    body = json.dumps({k: v for k, v in model.items() if k != "created_at"}, sort_keys=True, ensure_ascii=False)
    model["version"] = f"{MODEL_VERSION_PREFIX}-{hashlib.sha256(body.encode()).hexdigest()[:10]}"
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(model, f, ensure_ascii=False, indent=1)
    return model


def evaluate(dataset_root: str, split_file: str, model_path: str, system_report: Optional[str] = None) -> Dict[str, Any]:
    from ingest.split import load_split
    with open(model_path, encoding="utf-8") as f:
        model = json.load(f)
    nodes = model["tree"]
    thr = model.get("decision_threshold", 0.5)
    split = load_split(split_file)
    test = _phishing_html(dataset_root, split, "test")
    _, legit_test = _legit_sets(dataset_root)

    def predict(html):
        prob, _ = DecisionTree.predict_proba_nodes(nodes, features_from_html(html))
        return prob >= thr

    phish_pred = {rel: predict(html) for rel, _, html in test}
    legit_pred = {i: predict(h) for i, h in legit_test}
    groups = collections.defaultdict(list)
    for rel, g, _ in test:
        groups[g].append(phish_pred[rel])
    tp = sum(phish_pred.values())
    fp = sum(legit_pred.values())
    report = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "model_version": model.get("version"), "split_file": os.path.basename(split_file),
        "test_phishing_html": len(test), "test_templates": len(groups),
        "recall": round(tp / len(test), 4) if test else None,
        "recall_by_template": round(sum(1 for v in groups.values() if sum(v) / len(v) >= 0.5) / len(groups), 4) if groups else None,
        "test_legitimate": len(legit_test), "false_positives": fp,
        "false_positive_rate": round(fp / len(legit_test), 4) if legit_test else None,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "feature_importance_top": dict(list(model["feature_importance"].items())[:8]),
        "caveats": [
            "legitimate objects are few and of a different nature (e-mail bodies, synthetic pages): the false-positive rate "
            "is a rough estimate, not a measurement on real login pages",
            "static HTML features only: no rendering, no brand, no text semantics",
        ],
    }
    if system_report and os.path.isfile(system_report):
        with open(system_report, encoding="utf-8") as f:
            rows = {o["object"]: o for o in json.load(f).get("objects", []) if o.get("group") == "phishing"}
        both = system_only = base_only = neither = 0
        for rel, pred in phish_pred.items():
            row = rows.get(os.path.join("file_for_case", rel))
            if not row:
                continue
            sys_det = row.get("verdict") in ("MALICIOUS", "SUSPICIOUS")
            both += pred and sys_det
            system_only += (not pred) and sys_det
            base_only += pred and not sys_det
            neither += (not pred) and not sys_det
        n = both + system_only + base_only + neither
        if n:
            report["comparison_with_pipeline"] = {
                "pipeline_report": os.path.basename(system_report), "objects": n,
                "pipeline_recall": round((both + system_only) / n, 4), "baseline_recall": round((both + base_only) / n, 4),
                "both": both, "pipeline_only": system_only, "baseline_only": base_only, "neither": neither}
    return report
