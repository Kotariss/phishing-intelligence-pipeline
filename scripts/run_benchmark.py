"""
Quality benchmark (ТЗ п. 4.1.11): runs the pipeline offline over the customer corpus and the
known-legitimate set and writes a JSON metrics report.

    python scripts/run_benchmark.py --limit 50 --sources keis2,html,png --out reports/metrics.json
"""
import argparse
import json
import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DATABASE_URL", "sqlite:///" + os.path.join(ROOT_DIR, "reports", "benchmark.db").replace("\\", "/"))
os.environ.setdefault("EXPORTS_DIR", os.path.join(ROOT_DIR, "reports", "benchmark_exports"))
os.environ.setdefault("SANDBOX_INPROCESS_FALLBACK", "true")
sys.path.insert(0, os.path.join(ROOT_DIR, "services", "worker", "src"))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass


def main():
    parser = argparse.ArgumentParser(description="DW-2 Phishing Intelligence Pipeline — quality benchmark")
    parser.add_argument("--dataset", default=os.path.join(ROOT_DIR, "file_for_case"))
    parser.add_argument("--limit", type=int, default=None, help="objects per source (default: all)")
    parser.add_argument("--sources", default="keis2,html,png")
    parser.add_argument("--out", default=os.path.join(ROOT_DIR, "reports", "metrics.json"))
    parser.add_argument("--llm", choices=["off", "local", "cloud"], default=None,
                        help="override LLM_MODE for this run (default: from .env)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    if args.llm:
        os.environ["LLM_MODE"] = args.llm
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)

    from evaluation import evaluate, save_report
    report = evaluate(args.dataset, args.limit, tuple(args.sources.split(",")),
                      progress=print if args.verbose else None)
    save_report(report, args.out)
    print(json.dumps({"counts": report["counts"], "metrics": report["metrics"], "acceptance": report["acceptance"]},
                     ensure_ascii=False, indent=2))
    print(f"Report: {args.out}")


if __name__ == "__main__":
    main()
