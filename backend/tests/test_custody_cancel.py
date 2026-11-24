"""Cancelling a pending custody transfer (append-only: a TRANSFER_CANCELLED event is added)."""
from .test_dfis import A, mkcase, up


def _uid(client, h):
    return client.get(f"{A}/auth/me", headers=h).json()["id"]


def _start_transfer(client, users, title):
    h = users["lead1"]; c = mkcase(client, h, title); e = up(client, h, c["id"]).json()
    r = client.post(f"{A}/chain-of-custody/{e['id']}/transfer", headers=h,
                    json={"to_user_id": _uid(client, users["lead2"]), "reason": "wrong person"})
    assert r.status_code == 200, r.text
    return e, r.json()["event_id"]


def _record(client, h, eid):
    return client.get(f"{A}/chain-of-custody/{eid}", headers=h).json()


def test_sender_cancels_pending_transfer(client, users):
    h = users["lead1"]
    e, tid = _start_transfer(client, users, "Cancel ok")
    assert _record(client, h, e["id"])["evidence"]["status"] == "transfer_pending"

    # Reason is mandatory.
    assert client.post(f"{A}/chain-of-custody/{e['id']}/cancel/{tid}", headers=h, json={"reason": ""}).status_code == 422
    r = client.post(f"{A}/chain-of-custody/{e['id']}/cancel/{tid}", headers=h, json={"reason": "Wrong recipient selected"})
    assert r.status_code == 200, r.text

    rec = _record(client, h, e["id"])
    assert rec["evidence"]["status"] == "in_custody"
    actions = [x["action"] for x in rec["events"]]
    assert actions == ["INGESTED", "TRANSFER", "TRANSFER_CANCELLED"]  # nothing deleted
    transfer = next(x for x in rec["events"] if x["action"] == "TRANSFER")
    assert transfer["ack_status"] == "cancelled"
    cancel = rec["events"][-1]
    assert cancel["reason"] == "Wrong recipient selected" and cancel["ref_event_id"] == tid

    # The intended recipient can no longer acknowledge, and it can't be cancelled twice.
    assert client.post(f"{A}/chain-of-custody/{e['id']}/acknowledge/{tid}", headers=users["lead2"]).status_code == 409
    assert client.post(f"{A}/chain-of-custody/{e['id']}/cancel/{tid}", headers=h, json={"reason": "again please"}).status_code == 409
    # Evidence can be transferred again afterwards.
    r = client.post(f"{A}/chain-of-custody/{e['id']}/transfer", headers=h,
                    json={"to_user_id": _uid(client, users["lead2"]), "reason": "correct person"})
    assert r.status_code == 200


def test_acknowledged_transfer_cannot_be_cancelled(client, users):
    e, tid = _start_transfer(client, users, "Cancel late")
    assert client.post(f"{A}/chain-of-custody/{e['id']}/acknowledge/{tid}", headers=users["lead2"]).status_code == 200
    r = client.post(f"{A}/chain-of-custody/{e['id']}/cancel/{tid}", headers=users["lead1"], json={"reason": "too late now"})
    assert r.status_code == 409


def test_roles_without_custody_permission_cannot_cancel(client, users):
    e, tid = _start_transfer(client, users, "Cancel perm")
    r = client.post(f"{A}/chain-of-custody/{e['id']}/cancel/{tid}", headers=users["ana1"], json={"reason": "not allowed"})
    assert r.status_code in (403, 404)


def test_unassigned_lead_recipient_is_assigned_and_can_acknowledge(client, users):
    """A lead not on the case receives evidence: they get case access and can acknowledge."""
    e, tid = _start_transfer(client, users, "Recipient access")
    h2 = users["lead2"]
    assert client.get(f"{A}/evidence/{e['id']}", headers=h2).status_code == 200
    rec = _record(client, h2, e["id"])
    assert any(x["id"] == tid and x["ack_status"] == "pending" for x in rec["events"])
    assert client.post(f"{A}/chain-of-custody/{e['id']}/acknowledge/{tid}", headers=h2).status_code == 200
    assert _record(client, h2, e["id"])["evidence"]["status"] == "in_custody"
