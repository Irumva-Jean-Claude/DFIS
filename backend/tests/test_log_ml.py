"""Log overview statistics, AI intrusion scan on evidence, and audit-chain verification."""
from pathlib import Path

from .test_dfis import A, mkcase, up

TEST_DATA = Path(__file__).resolve().parents[2] / "test-data"


def test_log_stats_overview(client, users):
    h = users["lead1"]; c = mkcase(client, h, "Log stats")
    log = "\n".join(f"Oct 19 10:00:0{i} srv sshd[1]: Failed password for root from 203.0.113.7 port 22" for i in range(6))
    e = up(client, h, c["id"], name="auth.log", data=log.encode(), evidence_type="system_log").json()
    assert client.post(f"{A}/log-analysis/{e['id']}", headers=h).json()["status"] == "completed"

    s = client.get(f"{A}/log-analysis/{e['id']}/stats", headers=h).json()
    assert {"label": "auth_failure", "value": 6} in s["by_type"]
    assert s["top_failed_ips"][0] == {"label": "203.0.113.7", "value": 6}
    assert s["top_users"][0]["label"] == "root"
    assert sum(b["total"] for b in s["timeline"]) == 6
    assert sum(b["failures"] for b in s["timeline"]) == 6
    # Another lead with no access to the case must not see the stats.
    assert client.get(f"{A}/log-analysis/{e['id']}/stats", headers=users["lead2"]).status_code == 404


def test_intrusion_scan_on_evidence(client, users):
    if not client.get(f"{A}/ml/status").json()["model_loaded"]:
        import pytest; pytest.skip("ML model not available")
    h = users["lead1"]; c = mkcase(client, h, "Network scan")
    data = (TEST_DATA / "network_connections.csv").read_bytes()
    e = up(client, h, c["id"], name="net.csv", data=data, evidence_type="system_log").json()

    job = client.post(f"{A}/ml/intrusion-detect/{e['id']}", headers=h).json()
    assert job["status"] == "completed", job
    r = job["result"]
    assert r["source"] == "evidence"
    assert r["total_connections"] == 33
    assert r["attacks_detected"] + r["normal_detected"] == 33
    assert r["attacks_detected"] > 0
    assert "evaluation" in r and r["evaluation"]["accuracy"] is not None
    # Attacks are listed first.
    assert r["results"][0]["prediction"] == "Attack"

    latest = client.get(f"{A}/ml/intrusion-detect/{e['id']}/latest", headers=h).json()
    assert latest["id"] == job["id"]


def test_intrusion_scan_rejects_non_kdd_file(client, users):
    if not client.get(f"{A}/ml/status").json()["model_loaded"]:
        import pytest; pytest.skip("ML model not available")
    h = users["lead1"]; c = mkcase(client, h, "Bad scan")
    e = up(client, h, c["id"], name="notes.csv", data=b"a,b,c\n1,2,3\n").json()
    job = client.post(f"{A}/ml/intrusion-detect/{e['id']}", headers=h).json()
    assert job["status"] == "failed"
    assert "NSL-KDD" in job["error"]


def test_audit_chain_verify_reports_valid(client, admin):
    r = client.get(f"{A}/audit/verify", headers=admin).json()
    assert r["valid"] is True, r
    assert r["checked"] > 0
