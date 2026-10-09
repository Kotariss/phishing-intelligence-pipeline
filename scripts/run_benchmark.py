"""
Phishing Intelligence Pipeline — Batch Evaluation Benchmark
Tests pipeline against real phishing datasets and benign baseline to measure TPR and verify Zero FPR.
"""

import os
import sys
import argparse
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass

# Add paths
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT_DIR, "services", "worker", "src"))
sys.path.insert(0, os.path.join(ROOT_DIR, "services", "sandbox", "src"))

from orchestrator.state import PhishingState
from orchestrator.graph import run_pipeline
from rules.zero_fpr_guard import BENIGN_BASELINE_CORPUS

def run_benchmark(sample_limit: int = 5, verbose: bool = False):
    print("=" * 70)
    print("Phishing Intelligence Pipeline — Benchmark Suite")
    print("=" * 70)

    phish_tp = 0
    phish_fn = 0
    benign_tn = 0
    benign_fp = 0
    generated_l_sigs = 0
    generated_yaras = 0

    start_time = time.time()

    # Category 1: Russian Phishing EMLs (keis2)
    print("\n[1/4] Testing Target Brand Phishing (keis2: Sber, Gosuslugi, T-Bank, VTB)...")
    keis2_dir = os.path.join(ROOT_DIR, "file_for_case", "keis2")
    brand_subdirs = ["Сбер", "Госуслуги", "Т-Банк", "ВТБ"]
    
    tested_c1 = 0
    for b in brand_subdirs:
        b_path = os.path.join(keis2_dir, b)
        if not os.path.isdir(b_path):
            continue
        for sample_hash in os.listdir(b_path)[:sample_limit]:
            hash_path = os.path.join(b_path, sample_hash)
            if not os.path.isdir(hash_path):
                continue
            
            # Find the eml file (has same name as directory)
            eml_file = os.path.join(hash_path, sample_hash)
            if not os.path.isfile(eml_file):
                continue
            
            with open(eml_file, "rb") as f:
                content = f.read()

            state = PhishingState(
                incident_id=f"bm_c1_{sample_hash[:6]}",
                source_type="eml",
                raw_target=eml_file,
                raw_bytes=content
            )
            res = run_pipeline(state)
            tested_c1 += 1
            if res.verdict in ("MALICIOUS", "SUSPICIOUS"):
                phish_tp += 1
            else:
                phish_fn += 1

            if res.generated_l_signature:
                generated_l_sigs += 1
            if res.generated_yara_rule:
                generated_yaras += 1

            if verbose:
                print(f"  [{b}] {sample_hash[:10]} -> {res.verdict} (Score: {res.risk_score:.2f}) Codes: {res.reason_codes}")

    print(f"  -> Tested {tested_c1} target brand EML samples.")

    # Category 2: Offline HTML Phishing Kits
    print("\n[2/4] Testing Offline HTML Phishing Kits (html_phishing2026)...")
    html_dir = os.path.join(ROOT_DIR, "file_for_case", "html_phishing2026")
    html_files = [f for f in os.listdir(html_dir) if f.endswith(".html")][:sample_limit]
    
    tested_c2 = 0
    for hf in html_files:
        fpath = os.path.join(html_dir, hf)
        with open(fpath, "rb") as f:
            content = f.read()

        state = PhishingState(
            incident_id=f"bm_c2_{hf[:6]}",
            source_type="html",
            raw_target=fpath,
            raw_bytes=content
        )
        res = run_pipeline(state)
        tested_c2 += 1
        if res.verdict in ("MALICIOUS", "SUSPICIOUS"):
            phish_tp += 1
        else:
            phish_fn += 1

        if res.generated_l_signature:
            generated_l_sigs += 1
        if res.generated_yara_rule:
            generated_yaras += 1

        if verbose:
            print(f"  [HTML] {hf[:12]} -> {res.verdict} (Score: {res.risk_score:.2f}) Codes: {res.reason_codes}")

    print(f"  -> Tested {tested_c2} HTML phishing kits.")

    # Category 3: Visual Lures & Double Extensions
    print("\n[3/4] Testing Visual Lures & Double Extensions (grouped_png_phishing2026)...")
    png_dir = os.path.join(ROOT_DIR, "file_for_case", "grouped_png_phishing2026")
    tested_c3 = 0
    for cluster in ["cluster_1", "cluster_10", "cluster_12"]:
        c_path = os.path.join(png_dir, cluster)
        if not os.path.isdir(c_path):
            continue
        for pf in os.listdir(c_path)[:sample_limit]:
            fpath = os.path.join(c_path, pf)
            with open(fpath, "rb") as f:
                content = f.read()

            state = PhishingState(
                incident_id=f"bm_c3_{pf[:6]}",
                source_type="png",
                raw_target=fpath,
                raw_bytes=content
            )
            res = run_pipeline(state)
            tested_c3 += 1
            if res.verdict in ("MALICIOUS", "SUSPICIOUS"):
                phish_tp += 1
            else:
                phish_fn += 1

            if res.generated_l_signature:
                generated_l_sigs += 1
            if res.generated_yara_rule:
                generated_yaras += 1

            if verbose:
                print(f"  [PNG] {pf[:16]} -> {res.verdict} (Score: {res.risk_score:.2f}) Codes: {res.reason_codes}")

    print(f"  -> Tested {tested_c3} visual lure images.")

    # Category 4: Zero FPR Verification on Benign Baseline
    print("\n[4/4] Testing Benign Baseline for Zero FPR Guarantee...")
    tested_c4 = len(BENIGN_BASELINE_CORPUS)
    for sample in BENIGN_BASELINE_CORPUS:
        state = PhishingState(
            incident_id=f"bm_benign_{sample['id']}",
            source_type="url",
            raw_target=sample["url"]
        )
        res = run_pipeline(state)
        if res.verdict == "CLEAN":
            benign_tn += 1
        else:
            benign_fp += 1

        if verbose:
            print(f"  [BENIGN] {sample['url']} -> {res.verdict} (Score: {res.risk_score:.2f}) FP: {res.verdict != 'CLEAN'}")

    print(f"  -> Tested {tested_c4} benign business samples.")

    # Metrics computation
    total_phish = phish_tp + phish_fn
    tpr = (phish_tp / total_phish * 100.0) if total_phish > 0 else 0.0

    total_benign = benign_tn + benign_fp
    fpr = (benign_fp / total_benign * 100.0) if total_benign > 0 else 0.0

    elapsed = time.time() - start_time

    print("\n" + "=" * 70)
    print("[FINAL BENCHMARK EVALUATION RESULTS]")
    print("=" * 70)
    print(f"Total Execution Time:        {elapsed:.2f} s")
    print(f"Phishing Samples Analyzed:   {total_phish}")
    print(f"  - True Positives (TP):     {phish_tp}")
    print(f"  - False Negatives (FN):    {phish_fn}")
    print(f"  - Detection Rate (TPR):    {tpr:.1f}% (Target: > 90.0%)")
    print(f"Benign Samples Analyzed:     {total_benign}")
    print(f"  - True Negatives (TN):     {benign_tn}")
    print(f"  - False Positives (FP):    {benign_fp}")
    print(f"  - False Positive Rate:     {fpr:.2f}% (Target: 0.00% Zero FPR)")
    print(f"Active L-Signatures Made:    {generated_l_sigs}")
    print(f"Active YARA Rules Made:      {generated_yaras}")
    print("=" * 70)

    if fpr == 0.0:
        print("[VERIFIED] ZERO FPR STANDARD: FULLY VERIFIED (0.00% FP on business traffic)")
    else:
        print(f"[ALERT] ZERO FPR STANDARD: VIOLATED ({fpr:.2f}% FP)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DW-2 Phishing Intelligence Pipeline Benchmark")
    parser.add_argument("--limit", type=int, default=5, help="Number of samples per category to test")
    parser.add_argument("--verbose", action="store_true", help="Print per-sample results")
    args = parser.parse_args()

    run_benchmark(sample_limit=args.limit, verbose=args.verbose)
