import sys
import os
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT_DIR, "services", "sandbox", "src"))

from security import validate_url_safety, SecurityError

def test_ssrf_loopback_blocked():
    safe, msg = validate_url_safety("http://127.0.0.1:8080/admin")
    assert safe is False
    assert "127.0.0.0/8" in msg or "prohibited" in msg

def test_ssrf_localhost_blocked():
    safe, msg = validate_url_safety("http://localhost:8501")
    assert safe is False
    assert "prohibited" in msg

def test_ssrf_rfc1918_private_ips_blocked():
    for ip in ["10.0.0.5", "172.16.1.1", "192.168.1.1"]:
        safe, msg = validate_url_safety(f"http://{ip}/config")
        assert safe is False, f"Failed to block {ip}"

def test_ssrf_cloud_metadata_blocked():
    safe, msg = validate_url_safety("http://169.254.169.254/latest/meta-data/")
    assert safe is False

def test_disallowed_schemes():
    for bad_url in ["file:///etc/passwd", "ftp://evil.com/mal", "gopher://bad.org"]:
        safe, msg = validate_url_safety(bad_url)
        assert safe is False
        assert "Prohibited scheme" in msg

def test_valid_public_url():
    safe, msg = validate_url_safety("https://sberbank.ru/ru/person")
    assert safe is True
