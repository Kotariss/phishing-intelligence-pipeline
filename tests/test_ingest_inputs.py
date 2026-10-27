"""ТЗ 4.1.1.1, 4.1.1.3 / ПМИ А-1: URL list, ZIP archive, duplicates and provenance."""
import hashlib
import io
import os
import zipfile

import pytest

import cli
from db.repository import IncidentRepository
from helpers import run_file
from test_attachment_parser import _eml_with_html_attachment


def test_url_list_file_expands_to_urls(tmp_path):
    f = tmp_path / "urls.txt"
    f.write_text("# list\nhttps://a.example/x\n\nhttp://b.example/y\n", encoding="utf-8")
    assert cli._url_list(str(f)) == ["https://a.example/x", "http://b.example/y"]
    assert list(cli._iter_objects(str(f))) == ["https://a.example/x", "http://b.example/y"]
    plain = tmp_path / "notes.txt"
    plain.write_text("hello world", encoding="utf-8")
    assert cli._url_list(str(plain)) is None


def test_zip_archive_is_unpacked_and_traversal_is_skipped(tmp_path):
    z = tmp_path / "objs.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a/page.html", "<html><body>x</body></html>")
        zf.writestr("../../evil.html", "<html>evil</html>")
    objs = list(cli._iter_objects(str(z)))
    assert len(objs) == 1 and objs[0].endswith("page.html") and os.path.isfile(objs[0])
    assert not os.path.exists(os.path.join(str(tmp_path), "evil.html"))


def test_archive_limits(tmp_path, monkeypatch):
    z = tmp_path / "many.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for i in range(5):
            zf.writestr(f"{i}.html", "x")
    monkeypatch.setattr(cli, "ARCHIVE_MAX_FILES", 3)
    with pytest.raises(ValueError):
        list(cli._iter_objects(str(z)))


def test_same_email_analysed_twice_is_marked_as_duplicate_with_provenance():
    raw = _eml_with_html_attachment()
    first = run_file("dup_a.eml", raw)
    second = run_file("dup_b.eml", raw)
    assert first.duplicate_of is None
    assert second.duplicate_of == first.incident_id
    assert second.object_sha256 == hashlib.sha256(raw).hexdigest()
    row = IncidentRepository().get_incident(second.incident_id)
    assert row.duplicate_of == first.incident_id and row.created_at and row.raw_target == "dup_b.eml" and row.source_type
    assert second.ingested_at
