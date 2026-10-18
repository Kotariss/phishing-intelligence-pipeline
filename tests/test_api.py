"""REST API (ТЗ п. 4.8.1.2): analyse an object, fetch results, knowledge-base stats, export the package."""
import pytest
from fastapi.testclient import TestClient

from helpers_demo import TELEGRAM_KIT


@pytest.fixture(scope="module")
def client():
    # both services have a `main` module: load the worker's explicitly
    import importlib.util
    import os
    from conftest import ROOT_DIR
    spec = importlib.util.spec_from_file_location("worker_main", os.path.join(ROOT_DIR, "services", "worker", "src", "main.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with TestClient(module.app) as c:
        yield c


def test_health(client):
    body = client.get("/health").json()
    assert body["status"] == "healthy" and body["llm_mode"] == "local" and body["llm_ready"] is True


def test_scan_file_then_fetch_result(client):
    r = client.post("/api/v1/scan", files={"file": ("invoice.pdf.html", TELEGRAM_KIT.encode("utf-8"))})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "MALICIOUS" and body["reason_details"] and "raw_bytes" not in body
    detail = client.get(f"/api/v1/incidents/{body['incident_id']}")
    assert detail.status_code == 200 and detail.json()["verdict"] == "MALICIOUS"
    assert client.get("/api/v1/incidents/does-not-exist").status_code == 404


def test_garbage_input_does_not_crash(client):
    r = client.post("/api/v1/scan", files={"file": ("x.bin", b"\x00\x01garbage")})
    assert r.status_code == 200 and r.json()["verdict"] in ("CLEAN", "SUSPICIOUS")


def test_url_validation(client):
    assert client.post("/api/v1/scan", data={"url": "ftp://example.com"}).status_code == 400
    assert client.post("/api/v1/scan").status_code == 400


def test_stats_campaigns_package(client):
    assert client.get("/api/v1/stats").json()["total_incidents"] >= 1
    assert client.get("/api/v1/campaigns").status_code == 200
    pkg = client.post("/api/v1/package").json()
    assert pkg["version"] and pkg["package"]["format"].startswith("dw2-artifact-package/")
    assert client.get("/api/v1/signatures/export-zip").headers["content-type"] == "application/zip"
