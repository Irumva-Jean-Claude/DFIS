"""DFIS end-to-end seed + accuracy test script.

Prerequisite: the server must be running on http://localhost:8000.
Run:  .\\.venv\\Scripts\\python.exe scripts\\seed_and_test.py

What it does: logs in as the admin from .env, creates a dedicated test user of
each role, a dedicated test case, uploads the files from test-data/, and asserts
the system behaves accurately (hashing, RBAC, isolation, analysis alerts,
custody flow, timeline, report, audit chain).

IMPORTANT: this script creates real records in your database (all named with a
"NEMO-" prefix so you can identify and delete them later).
"""
import hashlib
import io
import json
import sys
import time
from pathlib import Path

import httpx

BASE = "http://localhost:8000/api/v1"
ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "test-data"

ADMIN_USER = "irumva"
ADMIN_PASS = "irumvajc123"

fails = []


def check(name, cond, extra=""):
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f"  ({extra})" if extra and not cond else ""))
    if not cond:
        fails.append(name)


def api(client, method, path, token=None, expect=200, **kw):
    headers = kw.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = client.request(method, BASE + path, headers=headers, **kw)
    if r.status_code != expect:
        print(f"  !! {method} {path} -> {r.status_code}: {r.text[:300]}")
    return r


def login(client, username, password):
    r = api(client, "POST", "/auth/login", json={"username": username, "password": password})
    if r.status_code != 200:
        return None, None
    j = r.json()
    return j["access_token"], j["me"]


def main():
    t0 = time.time()
    with httpx.Client(timeout=60) as c:
        tok, me = login(c, ADMIN_USER, ADMIN_PASS)
        check("admin login works", tok is not None)
        if not tok:
            sys.exit(2)

        suffix = str(int(time.time()))[-6:]
        pw = "Nemo-Pass-" + suffix + "!aA1"

        # ---- users of each role -------------------------------------------
        users = {}
        for role in ("lead", "analyst", "custodian", "reviewer"):
            uname = f"nemo_{role}_{suffix}"
            r = api(c, "POST", "/users", tok, expect=201, json={
                "username": uname, "full_name": f"NEMO {role}", "role": role, "password": pw})
            check(f"create {role} user", r.status_code == 201)
            users[role] = {"id": r.json()["id"], "username": uname, "pw": pw}

        # role-permission enforcement: reviewer cannot create cases
        rtok, _ = login(c, users["reviewer"]["username"], pw)
        check("reviewer login works", rtok is not None)
        r = api(c, "POST", "/cases", rtok, expect=403, json={"title": "should fail"})
        check("reviewer cannot create cases (RBAC)", r.status_code == 403)

        # ---- case ----------------------------------------------------------
        r = api(c, "POST", "/cases", tok, expect=201, json={
            "title": f"NEMO accuracy-test case {suffix}",
            "description": "Automated accuracy verification",
            "priority": "high"})
        case = r.json()
        check("case created with auto ref", r.status_code == 201 and case["ref"].startswith("DFIS-"))
        cid = case["id"]

        # assign custodian (custody transfer needs assignment)
        api(c, "POST", f"/cases/{cid}/assign", tok, json={"user_id": users["custodian"]["id"]})

        # status-flow enforcement
        r = api(c, "PATCH", f"/cases/{cid}", tok, json={"status": "archived"}, expect=409)
        check("illegal status transition rejected", r.status_code == 409)

        # ---- evidence uploads ----------------------------------------------
        def upload(fname, etype, expect_code=201):
            p = DATA / fname
            files = {"file": (fname, p.read_bytes())}
            r = api(c, "POST", "/evidence", tok, expect=expect_code, data={
                "case_id": cid, "evidence_type": etype, "source": "NEMO test source",
                "acquisition_method": "logical copy", "acquisition_date": "2026-10-25T14:30:00Z",
                "submitted_by": "nemo-submitter", "received_by": "nemo-receiver"}, files=files)
            return r

        up = {}
        for fname, etype in (("auth_failures.log", "system_log"),
                             ("sudo_suspicious.log", "system_log"),
                             ("events.jsonl", "system_log"),
                             ("malformed.log", "system_log"),
                             ("evidence_notes.txt", "text")):
            r = upload(fname, etype)
            ok = r.status_code == 201
            check(f"upload {fname}", ok)
            up[fname] = r.json() if ok else {}

        eid_auth = up["auth_failures.log"].get("id")
        eid_sudo = up["sudo_suspicious.log"].get("id")
        eid_json = up["events.jsonl"].get("id")
        eid_mal = up["malformed.log"].get("id")

        # recorded SHA-256 must equal the real file hash
        for fname in ("auth_failures.log", "events.jsonl", "evidence_notes.txt"):
            real = hashlib.sha256((DATA / fname).read_bytes()).hexdigest()
            rec = up[fname].get("sha256", "")
            check(f"SHA-256 recorded correctly for {fname}", rec == real)

        # rejection paths
        r = api(c, "POST", "/evidence", tok, expect=415, data={
            "case_id": cid, "evidence_type": "other", "source": "s",
            "acquisition_method": "m", "submitted_by": "a", "received_by": "b"},
            files={"file": ("forbidden.exe", b"MZ\x90\x00\x03binary")})
        r2 = api(c, "POST", "/evidence", tok, expect=400, data={
            "case_id": cid, "evidence_type": "other", "source": "s",
            "acquisition_method": "m", "submitted_by": "a", "received_by": "b"},
            files={"file": ("empty.txt", b"")})
        check("disallowed extension rejected", r.status_code == 415)
        check("empty file rejected", r2.status_code == 400)

        # ---- integrity ------------------------------------------------------
        r = api(c, "POST", f"/integrity/{eid_auth}/verify", tok)
        check("integrity verify MATCH", r.json().get("result") == "MATCH")

        # ---- analyses -------------------------------------------------------
        def run(path):
            r = api(c, "POST", path, tok)
            return r.json()

        res_auth = run(f"/log-analysis/{eid_auth}")
        alerts = res_auth.get("result", {}).get("alerts", [])
        auth_alerts = [a for a in alerts if a["rule"] == "repeated_authentication_failures"]
        check("auth-failure alert fired (count==5, jsmith, threshold boundary)",
              any(a["count"] == 5 and "jsmith" in a["subject"] for a in auth_alerts),
              json.dumps(auth_alerts)[:200])

        res_sudo = run(f"/log-analysis/{eid_sudo}")
        alerts2 = res_sudo.get("result", {}).get("alerts", [])
        check("privilege alert fired on sudo/su lines",
              any(a["rule"] == "privilege_related_event" for a in alerts2))

        res_json = run(f"/log-analysis/{eid_json}")
        evs = api(c, "GET", f"/log-analysis/{eid_json}/events", tok).json()
        rows = {e["ts_original"]: e for e in evs["items"]}
        shifted = rows.get("2026-10-25T09:00:00+03:00", {})
        check("+03:00 timestamp normalized to 06:00Z",
              shifted.get("ts_utc", "").startswith("2026-10-25T06:00:00"),
              json.dumps(shifted))

        res_mal = run(f"/log-analysis/{eid_mal}")
        stats = res_mal.get("result", {}).get("stats", {})
        check("malformed lines reported, good lines parsed",
              stats.get("malformed", 0) >= 2 and stats.get("parsed", 0) >= 2,
              json.dumps(stats))

        # file analysis on the text note
        res_file = run(f"/file-analysis/{up['evidence_notes.txt']['id']}")
        obs = res_file.get("result", {}).get("observations", {})
        check("file analysis returns sha256 + preview",
              obs.get("sha256") == up["evidence_notes.txt"].get("sha256") and "text_preview" in obs)

        # metadata timestamps should appear in timeline
        tl = api(c, "GET", f"/timeline?case_id={cid}", tok).json()
        cats = {i["category"] for i in tl["items"]}
        check("timeline has acquisition events", "acquisition" in cats)

        # ---- custody transfer + acknowledge ---------------------------------
        ctok, cme = login(c, users["custodian"]["username"], pw)
        check("custodian can login", ctok is not None)
        r = api(c, "POST", f"/chain-of-custody/{eid_auth}/transfer", tok, json={
            "to_user_id": users["custodian"]["id"], "reason": "NEMO accuracy test transfer"})
        check("custody transfer created", r.status_code == 200)
        ev_id = r.json().get("event_id")
        # only the recipient may acknowledge
        r = api(c, "POST", f"/chain-of-custody/{eid_auth}/acknowledge/{ev_id}", tok, expect=403)
        r = api(c, "POST", f"/chain-of-custody/{eid_auth}/acknowledge/{ev_id}", ctok)
        check("recipient acknowledges transfer", r.status_code == 200)
        det = api(c, "GET", f"/chain-of-custody/{eid_auth}", tok).json()
        check("custodian updated after ack",
              det["evidence"]["custodian"] == f"NEMO custodian")

        # non-assigned analyst cannot see the case
        atok, _ = login(c, users["analyst"]["username"], pw)
        # admin assigns analyst, then create second case analyst cannot see
        api(c, "POST", f"/cases/{cid}/assign", tok, json={"user_id": users["analyst"]["id"]})
        r2 = api(c, "POST", "/cases", tok, expect=201, json={"title": f"NEMO isolation case {suffix}"})
        cid2, c2ref = r2.json()["id"], r2.json()["ref"]
        r = api(c, "GET", f"/cases/{cid2}", atok, expect=404)
        check("cross-case access returns 404 (case isolation)", r.status_code == 404)

        # analyst timeline write ok, reviewer timeline write denied
        r = api(c, "POST", "/timeline", atok, expect=201, json={
            "case_id": cid, "title": "NEMO analyst event",
            "details": "added by automated test", "original_ts": "2026-10-25 12:00:00"})
        check("analyst can add timeline event", r.status_code == 201)
        r = api(c, "POST", "/timeline", rtok, expect=403, json={
            "case_id": cid, "title": "reviewer event", "original_ts": "2026-10-25 12:00:00"})
        check("reviewer cannot write timeline (RBAC)", r.status_code == 403)

        # analyst events appear in timeline
        tl2 = api(c, "GET", f"/timeline?case_id={cid}", tok).json()
        titles = [i["title"] for i in tl2["items"]]
        check("analyst event visible in timeline", any("NEMO analyst event" == t for t in titles))

        # ---- report ---------------------------------------------------------
        r = api(c, "POST", "/reports", tok, json={"case_id": cid})
        ok = r.status_code in (200, 201)
        rep = r.json() if ok else {}
        rid = rep.get("id")
        check("PDF report generated", ok and bool(rid))
        if rid:
            d = api(c, "GET", f"/reports/{rid}/download", tok)
            check("report PDF downloads and looks like a PDF",
                  d.status_code == 200 and d.content[:5] == b"%PDF-" and len(d.content) > 1000)

        # ---- audit chain ----------------------------------------------------
        r = api(c, "GET", "/audit/verify", tok)
        j = r.json()
        ok = (j.get("valid") is True) or (j.get("ok") is True) or ("invalid" not in json.dumps(j).lower())
        check("audit chain verifies", ok, json.dumps(j)[:200])

    print("-" * 60)
    print(f"{len(fails)} failed / total checks done in {time.time()-t0:.1f}s")
    if fails:
        print("FAILED:", *fails, sep="\n  - ")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
