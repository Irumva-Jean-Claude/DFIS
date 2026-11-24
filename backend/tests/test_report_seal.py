"""Tamper-evident PDF reports: sealing, verification and stored-file integrity."""
import io

from backend.app import config
from backend.app.db import SessionLocal, Report
from .test_dfis import A, mkcase, up


def _report(client, h, title):
    c = mkcase(client, h, title)
    up(client, h, c["id"])
    r = client.post(f"{A}/reports", headers=h, json={"case_id": c["id"], "notes": "seal test"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert len(body["sha256"]) == 64
    pdf = client.get(f"{A}/reports/{body['id']}/download", headers=h)
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    return body, pdf.content


def _verify(client, h, data, name="report.pdf"):
    r = client.post(f"{A}/reports/verify", headers=h, files={"file": (name, io.BytesIO(data), "application/pdf")})
    assert r.status_code == 200, r.text
    return r.json()


def test_issued_report_verifies_as_authentic(client, users):
    h = users["lead1"]
    body, pdf = _report(client, h, "Seal ok")
    v = _verify(client, h, pdf)
    assert v["authentic"] is True
    assert v["ref"] == body["ref"] and v["sha256"] == body["sha256"]
    listed = client.get(f"{A}/reports", headers=h).json()
    assert any(x["id"] == body["id"] and x["signed"] for x in listed)
    # Read-only roles can verify too.
    assert _verify(client, users["rev1"], pdf)["authentic"] is True


def test_modified_report_fails_and_names_original(client, users):
    h = users["lead1"]
    body, pdf = _report(client, h, "Seal tamper")
    v = _verify(client, h, pdf + b"\n% edited\n")
    assert v["authentic"] is False
    assert v["claimed_ref"] == body["ref"]
    assert v["expected_sha256"] == body["sha256"]
    assert "modified" in v["message"]


def test_foreign_file_is_not_authentic(client, users):
    v = _verify(client, users["lead1"], b"%PDF-1.4 not a DFIS report", "fake.pdf")
    assert v["authentic"] is False and v["claimed_ref"] is None


def test_tampered_stored_copy_blocks_download(client, users):
    h = users["lead1"]
    body, _ = _report(client, h, "Stored tamper")
    with SessionLocal() as s:
        fn = s.get(Report, body["id"]).filename
    path = config.REPORTS / fn
    path.write_bytes(path.read_bytes() + b"x")
    assert client.get(f"{A}/reports/{body['id']}/download", headers=h).status_code == 409
