"""
Command-line interface (ТЗ п. 4.8.1.1).

    python phishctl.py import-corpus file_for_case
    python phishctl.py analyze <file | sample_dir | URL> [--json out.json]
    python phishctl.py analyze-dir <dir> [--out reports/results.jsonl] [--limit N]     # resumable
    python phishctl.py kb-stats
    python phishctl.py cluster [--min-size 2]
    python phishctl.py export-package [--out exports/package]
    python phishctl.py apply <package.json> <file|dir>...
    python phishctl.py split [--dev-share 0.3] [--seen-from reports/seen_objects.txt]   # dev / held-out test
    python phishctl.py metrics [--limit N] [--sources keis2,html,png] [--part dev|test] [--out reports/metrics.json]
    python phishctl.py baseline train|eval                                              # interpretable baseline
    python phishctl.py build-benign-corpus
"""
import argparse
import collections
import datetime
import hashlib
import json
import os
import sys
import time
import uuid

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SRC_DIR, "..", "..", ".."))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def _log(msg: str) -> None:
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


# ----------------------------------------------------------------------------- helpers
def _snapshot_state(html_path: str, url: str, screenshot: str = None):
    """A saved web page (HTML + optional screenshot) captured from `url` — analysed offline."""
    import base64
    from orchestrator.state import PhishingState
    with open(html_path, "rb") as f:
        link = {"url": url, "final_url": url, "html": f.read().decode("utf-8", errors="ignore"), "redirect_chain": []}
    if screenshot:
        with open(screenshot, "rb") as f:
            link["screenshot_base64"] = base64.b64encode(f.read()).decode("ascii")
    return PhishingState(incident_id=f"inc_{uuid.uuid4().hex[:10]}", source_type="url", raw_target=url,
                         offline_mode=True, precollected_links=[link])


def _state_for_target(target: str, offline: bool):
    from orchestrator.state import PhishingState
    from ingest.dataset import build_state_from_sample_dir, is_sample_dir
    incident_id = f"inc_{uuid.uuid4().hex[:10]}"
    if target.lower().startswith(("http://", "https://")):
        return PhishingState(incident_id=incident_id, source_type="url", raw_target=target, offline_mode=offline)
    if os.path.isdir(target) and is_sample_dir(target):
        return build_state_from_sample_dir(target, incident_id)
    with open(target, "rb") as f:
        data = f.read()
    ext = target.lower().rsplit(".", 1)[-1] if "." in os.path.basename(target) else "bin"
    return PhishingState(incident_id=incident_id, source_type=ext, raw_target=target, raw_bytes=data, offline_mode=offline)


def _brief(state) -> dict:
    return {
        "incident_id": state.incident_id,
        "object": state.raw_target,
        "verdict": state.verdict,
        "risk_score": state.risk_score,
        "brand": state.brand_evidence.detected_brand_name,
        "final_url": state.final_url,
        "reason_codes": state.reason_codes,
        "reason_details": state.reason_details,
        "campaign_id": state.campaign_id,
        "signature": (state.generated_l_signature or {}).get("rule_id"),
        "signature_status": state.signature_status,
    }


def _iter_objects(root: str):
    """Objects of a directory: dataset sample dirs (EML + Link_N) or individual files."""
    from ingest.dataset import is_sample_dir
    if is_sample_dir(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            if is_sample_dir(full):
                yield full
                dirnames.remove(d)
        for name in sorted(filenames):
            if name.lower().endswith((".json", ".txt", ".list", ".zip", ".pdf")) and "Link_" in dirpath:
                continue
            yield os.path.join(dirpath, name)


# ---------------------------------------------------------------------------- commands
def cmd_import_corpus(args):
    """Indexes the corpus: type, size, sha256, duplicates, provenance (ТЗ п. 4.1.1.3–4.1.1.4)."""
    sys.path.insert(0, os.path.join(REPO_ROOT, "services", "sandbox", "src"))
    from attachment_parser import sniff_file_kind
    index, by_hash, errors = [], collections.defaultdict(list), []
    imported_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    for dirpath, _, filenames in os.walk(args.root):
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except OSError as e:
                errors.append({"path": path, "error": str(e)})
                continue
            sha = hashlib.sha256(data).hexdigest()
            entry = {"path": os.path.relpath(path, args.root), "sha256": sha, "size": len(data),
                     "kind": sniff_file_kind(name, data), "source": os.path.relpath(dirpath, args.root).split(os.sep)[0],
                     "imported_at": imported_at}
            entry["duplicate_of"] = by_hash[sha][0] if by_hash[sha] else None
            by_hash[sha].append(entry["path"])
            index.append(entry)
    kinds = collections.Counter(e["kind"] for e in index)
    summary = {"root": os.path.abspath(args.root), "imported_at": imported_at, "files": len(index),
               "unique": len(by_hash), "duplicates": len(index) - len(by_hash), "unreadable": len(errors),
               "by_kind": dict(kinds)}
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "errors": errors, "objects": index}, f, ensure_ascii=False, indent=1)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    _log(f"index written to {args.out}")


def cmd_analyze(args):
    from orchestrator.graph import run_pipeline
    t0 = time.time()
    if args.url:
        state = run_pipeline(_snapshot_state(args.target, args.url, args.screenshot))
    else:
        state = run_pipeline(_state_for_target(args.target, offline=not args.online))
    brief = _brief(state)
    brief["seconds"] = round(time.time() - t0, 2)
    print(json.dumps(brief, ensure_ascii=False, indent=2))
    print("\n" + (state.explanation or ""))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(state.public_dump(), f, ensure_ascii=False, indent=2)
        _log(f"full result written to {args.json}")


def cmd_analyze_dir(args):
    """Batch analysis; resumable (skips objects already present in --out), never aborts on bad input."""
    from orchestrator.graph import run_pipeline
    done = set()
    if os.path.exists(args.out):
        with open(args.out, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    done.add(json.loads(line)["object"])
                except (ValueError, KeyError):
                    continue
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    counts = collections.Counter()
    processed = 0
    with open(args.out, "a", encoding="utf-8") as out:
        own_outputs = {os.path.abspath(args.out), os.path.abspath(os.path.splitext(args.out)[0] + "_summary.json")}
        for obj in _iter_objects(args.root):
            if os.path.abspath(obj) in own_outputs:
                continue
            if args.limit and processed >= args.limit:
                break
            if obj in done:
                counts["skipped_resume"] += 1
                continue
            processed += 1
            t0 = time.time()
            try:
                state = run_pipeline(_state_for_target(obj, offline=not args.online))
                row = _brief(state)
                row["status"] = "ok"
                counts[state.verdict] += 1
            except Exception as e:  # ТЗ 4.2.2: a broken object must not stop the batch
                row = {"object": obj, "status": "error", "error": f"{type(e).__name__}: {str(e)[:300]}"}
                counts["error"] += 1
            row["object"] = obj
            row["seconds"] = round(time.time() - t0, 2)
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
            out.flush()
            _log(f"{row.get('verdict', row['status']):10s} {obj}")
    summary_path = os.path.splitext(args.out)[0] + "_summary.json"
    summary = _batch_summary(args.out, args.root)
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(json.dumps({"this_run": dict(counts), "total": summary["verdicts"]}, ensure_ascii=False, indent=2))
    _log(f"summary written to {summary_path}")


def _batch_summary(results_path: str, root: str) -> dict:
    """Summary of a whole batch (all rows, including resumed runs) — ТЗ п. 4.1.9.3."""
    rows = []
    with open(results_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    ok = [r for r in rows if r.get("status") == "ok"]
    return {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "root": os.path.abspath(root),
        "results_file": os.path.abspath(results_path),
        "objects": len(rows),
        "processed_ok": len(ok),
        "errors": [{"object": r["object"], "error": r.get("error")} for r in rows if r.get("status") != "ok"],
        "verdicts": dict(collections.Counter(r["verdict"] for r in ok)),
        "technique_frequency": dict(collections.Counter(c for r in ok for c in r.get("reason_codes", [])).most_common()),
        "brands": dict(collections.Counter(r["brand"] for r in ok if r.get("brand")).most_common(30)),
        "campaigns": dict(collections.Counter(r["campaign_id"] for r in ok if r.get("campaign_id")).most_common(30)),
        "signatures": {"active": sum(1 for r in ok if r.get("signature_status") == "ACTIVE_VERIFIED"),
                       "draft": sum(1 for r in ok if r.get("signature_status") == "DRAFT_REQUIRES_TUNING")},
        "mean_seconds": round(sum(r.get("seconds", 0) for r in rows) / len(rows), 3) if rows else None,
    }


def cmd_kb_stats(args):
    from db.repository import IncidentRepository
    from db.database import SessionLocal
    from db.models import IncidentModel
    stats = IncidentRepository().count_stats()
    db = SessionLocal()
    try:
        incidents = db.query(IncidentModel).all()
        stats["top_brands"] = collections.Counter(i.target_brand for i in incidents if i.target_brand).most_common(15)
        stats["technique_frequency"] = collections.Counter(c for i in incidents for c in (i.reason_codes or [])).most_common(30)
        stats["campaigns"] = len({i.campaign_id for i in incidents if i.campaign_id})
    finally:
        db.close()
    print(json.dumps(stats, ensure_ascii=False, indent=2))


def cmd_cluster(args):
    from db.repository import IncidentRepository
    repo = IncidentRepository()
    if args.visual:
        print(json.dumps(repo.list_visual_clusters(max_distance=args.max_distance, min_size=args.min_size), ensure_ascii=False, indent=2))
        return
    print(json.dumps(repo.list_campaigns(min_size=args.min_size, limit=args.limit), ensure_ascii=False, indent=2))


def cmd_export_package(args):
    from rules.package import build_package, save_package
    info = save_package(build_package(), args.out)
    print(json.dumps(info, ensure_ascii=False, indent=2))


def cmd_apply(args):
    from rules.package import load_package
    from rules.light_engine import apply_to_file
    package = load_package(args.package)
    from ingest.dataset import load_sample_dir
    targets = []
    for t in args.targets:
        for obj in (_iter_objects(t) if os.path.isdir(t) else [t]):
            # a dataset sample directory is represented by its e-mail
            targets.append(load_sample_dir(obj)["eml_path"] if os.path.isdir(obj) else obj)
    verdicts = collections.Counter()
    for path in targets:
        try:
            res = apply_to_file(package, path)
        except Exception as e:
            res = {"object": path, "verdict": "ERROR", "error": str(e)}
        verdicts[res["verdict"]] += 1
        print(json.dumps(res, ensure_ascii=False))
    print(json.dumps(dict(verdicts), ensure_ascii=False))


def cmd_metrics(args):
    from evaluation import evaluate, save_report
    split = None
    if args.part:
        from ingest.split import load_split
        if not os.path.exists(args.split_file):
            raise SystemExit(f"split manifest {args.split_file} not found: run `phishctl.py split` first")
        split = load_split(args.split_file)
    report = evaluate(args.dataset, args.limit, tuple(args.sources.split(",")),
                      progress=_log if args.verbose else None, split=split, part=args.part, workers=args.workers)
    save_report(report, args.out)
    print(json.dumps({"counts": report["counts"], "metrics": report["metrics"], "acceptance": report["acceptance"]},
                     ensure_ascii=False, indent=2))
    _log(f"report written to {args.out}")


def cmd_split(args):
    """Leakage-free dev / held-out test split of the customer corpus (groups: brand, DOM template, cluster)."""
    from ingest.split import build_split, save_split
    seen = []
    if args.seen_from:
        for path in args.seen_from:
            with open(path, "r", encoding="utf-8") as f:
                if path.endswith(".txt"):  # one object path per line (absolute or relative to the dataset)
                    seen += [os.path.relpath(os.path.join(args.dataset, l.strip()), args.dataset) for l in f if l.strip()]
                else:
                    seen += [os.path.relpath(os.path.join(REPO_ROOT, o["object"]), args.dataset)
                             for o in json.load(f).get("objects", []) if o.get("group") == "phishing"]
    split = build_split(args.dataset, args.dev_share, seen)
    save_split(split, args.out)
    print(json.dumps({k: split[k] for k in ("version", "dev_share", "forced_dev_objects", "stats")}, ensure_ascii=False, indent=2))
    _log(f"split manifest written to {args.out}")


def cmd_baseline(args):
    """Interpretable baseline (decision tree on raw HTML features): train / evaluate (ТЗ 4.1.3.2, 4.1.11)."""
    import baseline
    if args.action == "train":
        model = baseline.train(args.dataset, args.split_file, args.out)
        print(json.dumps({k: model[k] for k in ("version", "algorithm", "training", "feature_importance")}, ensure_ascii=False, indent=2))
        _log(f"baseline model written to {args.out}")
    else:
        report = baseline.evaluate(args.dataset, args.split_file, args.model, args.pipeline_report)
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=1)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        _log(f"baseline evaluation written to {args.out}")


def cmd_robustness(args):
    from evaluation import robustness, save_report
    from ingest.split import load_split
    report = {"generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "limit_per_source": args.limit,
              "part": args.part}
    split = load_split(args.split_file) if args.part else None
    scenarios = robustness(args.dataset, args.limit, progress=_log if args.verbose else None, split=split, part=args.part)
    report["excluded"] = scenarios.pop("_excluded")
    report["scenarios"] = scenarios
    save_report(report, args.out)
    print(json.dumps({k: {kk: v[kk] for kk in ("objects", "still_detected", "recall", "recall_drop")}
                      for k, v in report["scenarios"].items()}, ensure_ascii=False, indent=2))
    print(json.dumps(report["excluded"], ensure_ascii=False))
    _log(f"report written to {args.out}")


def cmd_eval_labeled(args):
    """Labelled e-mail test set: predictions for the set's compare_labels.py + summary."""
    from evaluation import evaluate_labeled_eml
    summary = evaluate_labeled_eml(args.root, args.out, limit=args.limit, progress=_log if args.verbose else None)
    print(json.dumps({k: v for k, v in summary.items() if not k.endswith("_ids") and k != "benign_code_frequency"},
                     ensure_ascii=False, indent=2))
    _log(f"predictions and results written to {args.out}")


def cmd_diff_runs(args):
    """Compares two runs object by object (verdict transitions and the indicators behind them)."""
    from evaluation import diff_runs, save_report
    diff = diff_runs(args.run_a, args.run_b, limit=args.limit)
    if args.out:
        save_report(diff, args.out)
    print(json.dumps({k: diff[k] for k in ("objects_a", "objects_b", "common", "transitions", "codes_appeared",
                                           "codes_disappeared")}, ensure_ascii=False, indent=2))
    for c in diff["changed_objects"][:args.show]:
        print(f"{c['before']:>10} -> {c['after']:<10} {c['object'][-70:]}  +{c['codes_added']} -{c['codes_removed']}")


def cmd_build_benign_corpus(args):
    sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
    import build_benign_corpus
    build_benign_corpus.main()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="phishctl", description="DW-2 Phishing Intelligence Pipeline")
    parser.add_argument("--llm", choices=["local", "cloud"], help="override LLM_MODE")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("import-corpus", help="index a corpus directory (types, hashes, duplicates)")
    p.add_argument("root")
    p.add_argument("--out", default=os.path.join(REPO_ROOT, "reports", "corpus_index.json"))
    p.set_defaults(func=cmd_import_corpus)

    p = sub.add_parser("analyze", help="analyse one object (file, dataset sample dir or URL)")
    p.add_argument("target")
    p.add_argument("--json", help="write the full JSON result")
    p.add_argument("--online", action="store_true", help="allow live URL fetching through the sandbox")
    p.add_argument("--url", help="treat TARGET as a saved page (HTML) captured from this URL")
    p.add_argument("--screenshot", help="screenshot of the saved page (with --url)")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("analyze-dir", help="batch-analyse a directory (resumable)")
    p.add_argument("root")
    p.add_argument("--out", default=os.path.join(REPO_ROOT, "reports", "results.jsonl"))
    p.add_argument("--limit", type=int)
    p.add_argument("--online", action="store_true")
    p.set_defaults(func=cmd_analyze_dir)

    p = sub.add_parser("kb-stats", help="knowledge-base statistics and technique frequency")
    p.set_defaults(func=cmd_kb_stats)

    p = sub.add_parser("cluster", help="phishing campaigns (incidents sharing kit / infrastructure)")
    p.add_argument("--min-size", type=int, default=2)
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--visual", action="store_true", help="group by alike screenshots (perceptual hash) instead")
    p.add_argument("--max-distance", type=int, default=8, help="dHash bits (of 64) that may differ in --visual")
    p.set_defaults(func=cmd_cluster)

    p = sub.add_parser("export-package", help="export a versioned artefact package (JSON + YARA)")
    p.add_argument("--out", default=os.path.join(REPO_ROOT, "exports", "package"))
    p.set_defaults(func=cmd_export_package)

    p = sub.add_parser("apply", help="apply a package with the light rule module")
    p.add_argument("package")
    p.add_argument("targets", nargs="+")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("metrics", help="compute the acceptance metrics and save a JSON report")
    p.add_argument("--dataset", default=os.path.join(REPO_ROOT, "file_for_case"))
    p.add_argument("--limit", type=int, help="objects per source")
    p.add_argument("--sources", default="keis2,html,png")
    p.add_argument("--out", default=os.path.join(REPO_ROOT, "reports", "metrics.json"))
    p.add_argument("--part", choices=("dev", "test"), help="only this part of the split manifest")
    p.add_argument("--split-file", default=os.path.join(REPO_ROOT, "reports", "split.json"))
    p.add_argument("--workers", type=int, default=1, help="parallel processes (useful with a remote LLM)")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_metrics)

    p = sub.add_parser("split", help="leakage-free dev / held-out test split of the customer corpus")
    p.add_argument("--dataset", default=os.path.join(REPO_ROOT, "file_for_case"))
    p.add_argument("--dev-share", type=float, default=0.3)
    p.add_argument("--seen-from", nargs="*", help="metrics reports whose objects were inspected (forced into dev)")
    p.add_argument("--out", default=os.path.join(REPO_ROOT, "reports", "split.json"))
    p.set_defaults(func=cmd_split)

    p = sub.add_parser("robustness", help="recall under domain/URL change, design change and delayed loading")
    p.add_argument("--dataset", default=os.path.join(REPO_ROOT, "file_for_case"))
    p.add_argument("--limit", type=int, default=30, help="objects per source")
    p.add_argument("--out", default=os.path.join(REPO_ROOT, "reports", "robustness.json"))
    p.add_argument("--part", choices=("dev", "test"), default="test", help="part of the split manifest (default: held-out)")
    p.add_argument("--split-file", default=os.path.join(REPO_ROOT, "reports", "split.json"))
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_robustness)

    p = sub.add_parser("eval-labeled", help="evaluate on a labelled EML set (manifest.csv with id/label/evidence_dir)")
    p.add_argument("root")
    p.add_argument("--out", default=os.path.join(REPO_ROOT, "reports", "labeled_eval"))
    p.add_argument("--limit", type=int)
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_eval_labeled)

    p = sub.add_parser("diff-runs", help="compare two runs (metrics .json or labelled-set output dir) object by object")
    p.add_argument("run_a")
    p.add_argument("run_b")
    p.add_argument("--out", help="write the full comparison as JSON")
    p.add_argument("--limit", type=int, default=500, help="changed objects kept in the JSON")
    p.add_argument("--show", type=int, default=40, help="changed objects printed")
    p.set_defaults(func=cmd_diff_runs)

    p = sub.add_parser("baseline", help="interpretable baseline classifier of HTML pages: train / eval")
    p.add_argument("action", choices=("train", "eval"))
    p.add_argument("--dataset", default=os.path.join(REPO_ROOT, "file_for_case"))
    p.add_argument("--split-file", default=os.path.join(REPO_ROOT, "reports", "split.json"))
    p.add_argument("--model", default=os.path.join(REPO_ROOT, "models", "baseline_v1.json"))
    p.add_argument("--out", help="train: model file (default --model); eval: report (default reports/baseline_eval.json)")
    p.add_argument("--pipeline-report", default=os.path.join(REPO_ROOT, "reports", "test_v3.json"),
                   help="eval: metrics report of the full pipeline on the same split, for the comparison")
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("build-benign-corpus", help="rebuild the known-legitimate feature corpus")
    p.set_defaults(func=cmd_build_benign_corpus)

    args = parser.parse_args(argv)
    if getattr(args, "func", None) is cmd_baseline:
        args.out = args.out or (args.model if args.action == "train" else os.path.join(REPO_ROOT, "reports", "baseline_eval.json"))
    if args.llm:
        os.environ["LLM_MODE"] = args.llm
    from llm.client import LLMUnavailable
    try:
        args.func(args)
    except LLMUnavailable as e:  # analysis requires the model; batch commands skip objects instead
        raise SystemExit(f"model unavailable: {e}")


if __name__ == "__main__":
    main()
