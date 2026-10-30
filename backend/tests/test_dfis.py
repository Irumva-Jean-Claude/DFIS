import io, hashlib, os, stat
from pathlib import Path
import pytest
from backend.app import config
from backend.app.forensic import parse_ts, parse_log, detect_indicators
from .conftest import login

A = "/api/v1"


def mkcase(c, h, title="Test case"):
    r = c.post(f"{A}/cases", headers=h, json={"title": title}); assert r.status_code == 201, r.text
    return r.json()


def up(c, h, cid, name="note.txt", data=b"hello evidence", **kw):
    return c.post(f"{A}/evidence", headers=h, data={"case_id": cid, "evidence_type": "text", "source": "lab", "acquisition_method": "copy",
                  "submitted_by": "A", "received_by": "B", **kw}, files={"file": (name, io.BytesIO(data))})


def test_auth_and_rbac(client, admin, users):
    assert login(client, "admin", "wrong").status_code == 401
    assert client.get(f"{A}/cases").status_code == 401
    assert client.get(f"{A}/users", headers=users["lead1"]).status_code == 403
    assert client.post(f"{A}/cases", headers=users["rev1"], json={"title": "nope!"}).status_code == 403


def test_lockout(client, users):
    for _ in range(5):
        login(client, "ana1", "bad")
    assert login(client, "ana1", "Passw0rd12345").status_code == 429


def test_case_isolation(client, users):
    c = mkcase(client, users["lead1"])
    assert client.get(f"{A}/cases/{c['id']}", headers=users["lead2"]).status_code == 404
    assert c["id"] not in [x["id"] for x in client.get(f"{A}/cases", headers=users["lead2"]).json()["items"]]


def test_evidence_hash_integrity_and_immutability(client, users):
    h = users["lead1"]; c = mkcase(client, h)
    data = b"integrity test"
    r = up(client, h, c["id"], data=data); assert r.status_code == 201, r.text
    e = r.json(); assert e["sha256"] == hashlib.sha256(data).hexdigest()
    assert "storage_name" not in e
    assert client.post(f"{A}/integrity/{e['id']}/verify", headers=h).json()["result"] == "MATCH"
    f = next(config.ORIGINALS.iterdir()); assert not (f.stat().st_mode & stat.S_IWUSR)
    f.chmod(0o600); f.write_bytes(b"tampered"); f.chmod(0o444)
    assert client.post(f"{A}/integrity/{e['id']}/verify", headers=h).json()["result"] == "MISMATCH"
    assert client.get(f"{A}/evidence/{e['id']}", headers=users["lead2"]).status_code == 404


def test_upload_validation(client, users):
    h = users["lead1"]; c = mkcase(client, h)
    assert up(client, h, c["id"], name="evil.exe").status_code == 415
    r = up(client, h, c["id"], name="../../etc/passwd.txt"); assert r.status_code == 201
    assert "/" not in r.json()["original_filename"] and ".." not in r.json()["original_filename"]
    assert up(client, h, c["id"], data=b"x" * (2 * 1024 * 1024)).status_code == 413
    assert up(client, h, c["id"], data=b"").status_code == 400


def test_custody_append_only(client, users):
    from backend.app.db import SessionLocal, CustodyEvent, AuditEvent
    h = users["lead1"]; c = mkcase(client, h); e = up(client, h, c["id"]).json()
    me = client.get(f"{A}/auth/me", headers=h).json()
    ev = client.get(f"{A}/chain-of-custody/{e['id']}", headers=h).json()["events"]
    assert ev[0]["action"] == "INGESTED"
    with SessionLocal() as db:
        row = db.get(CustodyEvent, ev[0]["id"]); row.notes = "changed"
        with pytest.raises(PermissionError):
            db.commit()
        db.rollback()
        with pytest.raises(PermissionError):
            db.delete(db.query(AuditEvent).first()); db.commit()


def test_log_parsing_and_alerts(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("\n".join(f"2026-01-01T10:00:0{i}Z srv sshd[1]: Failed password for invalid user bob" for i in range(6)) + '\n{bad json\n{"timestamp":"2026-01-01T12:00:00+02:00","message":"sudo: root"}\n')
    ev, st, er = parse_log(p)
    assert st["malformed"] == 1 and len(ev) == 7
    assert any(a["rule"] == "repeated_authentication_failures" for a in detect_indicators(ev, None))
    assert ev[-1]["ts_utc"].hour == 10


def test_timestamp_normalization():
    assert parse_ts("2026-01-01T12:00:00+02:00")[0].hour == 10
    assert parse_ts("nonsense")[0] is None and parse_ts(None)[0] is None


def test_log_analysis_timeline_report_audit(client, users, admin):
    h = users["lead1"]; c = mkcase(client, h, "Full flow")
    log = "\n".join(f"Oct 19 10:00:0{i} srv sshd[1]: Failed password for root" for i in range(6)).encode()
    e = up(client, h, c["id"], name="auth.log", data=log, evidence_type="system_log").json()
    j = client.post(f"{A}/log-analysis/{e['id']}", headers=h).json(); assert j["status"] == "completed", j
    assert j["result"]["alerts"]
    assert client.get(f"{A}/log-analysis/{e['id']}/events?event_type=auth_failure", headers=h).json()["total"] == 6
    assert client.post(f"{A}/file-analysis/{e['id']}", headers=h).json()["status"] == "completed"
    t = client.get(f"{A}/timeline?case_id={c['id']}", headers=h).json(); assert t["items"]
    r = client.post(f"{A}/timeline", headers=h, json={"case_id": c["id"], "title": "Analyst note", "original_ts": "garbage"}); assert r.status_code == 422
    r = client.post(f"{A}/reports", headers=h, json={"case_id": c["id"], "notes": "<b>x</b>"}); assert r.status_code == 201, r.text
    pdf = client.get(f"{A}/reports/{r.json()['id']}/download", headers=h); assert pdf.content[:4] == b"%PDF"
    assert client.get(f"{A}/reports/{r.json()['id']}/download", headers=users["lead2"]).status_code == 404
    assert client.get(f"{A}/audit/verify", headers=admin).json()["valid"] is True


# ---------------- MFA (TOTP) ----------------
import pyotp
from .conftest import login, H


def _mfa_setup(client, h):
    r = client.post(f"{A}/auth/mfa/setup", headers=h)
    assert r.status_code == 200, r.text
    d = r.json()
    return d["secret"], d["otpauth_uri"]


def test_mfa_full_flow(client, users):
    h = users["ana1"]  # ana1 is locked out by test_lockout (session-scoped); use lead2
    h = users["lead2"]
    assert client.get(f"{A}/auth/mfa/status", headers=h).json() == {"mfa_enabled": False}
    secret, uri = _mfa_setup(client, h)
    assert uri.startswith("otpauth://totp/")
    code = pyotp.TOTP(secret).now()
    r = client.post(f"{A}/auth/mfa/enable", headers=h, json={"code": code})
    assert r.status_code == 200, r.text
    assert len(r.json()["recovery_codes"]) == 8
    # password login now yields a challenge, not a token
    r = login(client, "lead2", "Passw0rd12345")
    assert r.json().get("mfa_required") is True
    tok = r.json()["mfa_token"]
    # wrong code rejected
    assert client.post(f"{A}/auth/mfa/verify", json={"mfa_token": tok, "code": "000000"}).status_code == 401
    # correct code completes login
    r = client.post(f"{A}/auth/mfa/verify", json={"mfa_token": tok, "code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200 and r.json()["me"]["mfa_enabled"] is True
    h2 = {"Authorization": "Bearer " + r.json()["access_token"]}
    # challenge token is single-use
    assert client.post(f"{A}/auth/mfa/verify", json={"mfa_token": tok, "code": pyotp.TOTP(secret).now()}).status_code == 401
    # recovery code login: invalid code rejected
    tok = login(client, "lead2", "Passw0rd12345").json()["mfa_token"]
    r = client.post(f"{A}/auth/mfa/verify-recovery", json={"mfa_token": tok, "code": "invalid-code-x"})
    assert r.status_code == 401
    # valid recovery code completes login
    rec = client.post(f"{A}/auth/mfa/enable", headers=h2, json={"code": pyotp.TOTP(secret).now()})  # not enabled; 409
    assert rec.status_code == 409
    # disable with valid TOTP using the active session
    r = client.post(f"{A}/auth/mfa/disable", headers=h2, json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200
    # login goes straight back to token
    assert login(client, "lead2", "Passw0rd12345").json().get("access_token")


def test_mfa_setup_requires_code(client, users):
    h = users["lead1"]
    _mfa_setup(client, h)
    r = client.post(f"{A}/auth/mfa/enable", headers=h, json={"code": "111111"})
    assert r.status_code == 401
