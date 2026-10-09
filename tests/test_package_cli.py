"""Artefact package (versioning, provenance, IOC separation), light rule module and CLI."""
import json
import os

from rules.package import build_package, save_package, load_package
from rules.light_engine import apply_package, record_for_object
from features.url_features import mask_url, is_shared_infrastructure
from helpers import run_page, TELEGRAM_KIT
import cli


def test_package_versioning_provenance_and_portability(tmp_path):
    state = run_page("https://kit-package-test.top/login", TELEGRAM_KIT)
    assert state.signature_status == "ACTIVE_VERIFIED"
    pkg = build_package()
    assert pkg["format"].startswith("dw2-artifact-package/")
    assert set(pkg) >= {"known_phishing_signatures", "rules", "brand_features", "reason_codes", "yara"}
    rule = next(r for r in pkg["rules"] if state.incident_id in r["provenance"]["incidents"])
    assert rule["kind"] == "exfil_channel"

    first = save_package(pkg, str(tmp_path))
    second = save_package(pkg, str(tmp_path))
    assert (first["version"], second["version"]) == ("1", "2")
    assert open(os.path.join(tmp_path, "LATEST")).read().startswith("2 ")

    # the light module detects the same kit on another host without any heavy extractor
    rec = record_for_object(TELEGRAM_KIT.encode("utf-8"), "page.html", url="https://other-host.example/x")
    assert apply_package(load_package(second["json"]), rec)["verdict"] == "MALICIOUS"
    benign = record_for_object(b"<html><title>Shop</title><form><input type='password'></form></html>",
                               "p.html", url="https://shop.example/login")
    assert apply_package(load_package(second["json"]), benign)["verdict"] == "CLEAN"


def test_shared_infrastructure_is_never_a_domain_ioc():
    assert is_shared_infrastructure("ok.me") and is_shared_infrastructure("x.pages.dev")
    assert not is_shared_infrastructure("csa-tech.info")
    domains = {d["domain"] for d in build_package()["known_phishing_signatures"]["domains"]}
    assert not domains & {"ok.me", "bit.ly", "pages.dev"}


def test_url_masking():
    assert mask_url("https://h.top/a/b?token=abc&u=me@x.ru") == "https://h.top/a/b?token=***&u=***"
    assert "***@***" in mask_url("https://h.top/u/john@corp.ru/x")


def test_cli_analyze_and_resumable_batch(tmp_path, capsys):
    sample = tmp_path / "page.html"
    sample.write_text(TELEGRAM_KIT, encoding="utf-8")
    broken = tmp_path / "broken.pdf"
    broken.write_bytes(b"%PDF-1.4 truncated")
    out_json = tmp_path / "res.json"
    cli.main(["analyze", str(sample), "--json", str(out_json)])
    assert json.loads(out_json.read_text(encoding="utf-8"))["verdict"] == "MALICIOUS"

    results = tmp_path / "batch.jsonl"
    cli.main(["analyze-dir", str(tmp_path), "--out", str(results)])
    rows = [json.loads(l) for l in results.read_text(encoding="utf-8").splitlines()]
    assert {r["status"] for r in rows} <= {"ok", "error"} and len(rows) >= 2
    cli.main(["analyze-dir", str(tmp_path), "--out", str(results)])  # resume: nothing re-processed
    assert len(results.read_text(encoding="utf-8").splitlines()) == len(rows)
    assert "skipped_resume" in capsys.readouterr().out


def test_cli_import_corpus_detects_duplicates(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "x.html").write_text("<html>same</html>", encoding="utf-8")
    (tmp_path / "y.html").write_text("<html>same</html>", encoding="utf-8")
    out = tmp_path / "index.json"
    cli.main(["import-corpus", str(tmp_path), "--out", str(out)])
    summary = json.loads(out.read_text(encoding="utf-8"))["summary"]
    assert summary["files"] == 2 and summary["duplicates"] == 1
