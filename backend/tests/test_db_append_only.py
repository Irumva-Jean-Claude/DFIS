"""Tests that the append-only ORM guards reject updates and deletes.

Covers the three layers installed in backend/app/db.py:
- per-class before_update / before_delete event listeners
- the session-wide before_flush guard (bulk Query.update / Query.delete)
- the SQLite RAISE(ABORT) triggers installed on connect
"""
import pytest

from backend.app import db
from backend.app.db import (AuditEvent, CustodyEvent, IntegrityCheck,
                            SessionLocal, now, uid)
from backend.app.security import _digest

APPEND_ONLY = [AuditEvent, CustodyEvent, IntegrityCheck]


def _seed_user_evidence(s, un, ref, storage):
    user = db.User(username=un, full_name=un.title(), password_hash="x", role="lead")
    s.add(user)
    s.flush()
    case = db.Case(ref=f"CASE-{un}", title="t", created_by=user.id)
    s.add(case)
    s.flush()
    ev = db.Evidence(ref=ref, case_id=case.id, evidence_type="file",
                     original_filename=storage, submitted_by="s", received_by="r",
                     mime="text/plain", size=1, sha256="0" * 64, hashed_at=now(),
                     storage_name=storage, uploaded_by=user.id)
    s.add(ev)
    s.flush()
    return user, case, ev


def _make_rows():
    """Insert one row of each append-only class; return {cls: key}."""
    s = SessionLocal()
    try:
        keys = {}
        for cls in APPEND_ONLY:
            row = cls()
            if cls is CustodyEvent:
                user, case, ev = _seed_user_evidence(s, "chainuser", "EV-CHAIN-1", "chain-a.txt")
                row.evidence_id, row.case_id, row.action, row.by_user_id = ev.id, case.id, "INGESTED", user.id
            elif cls is AuditEvent:
                # Chain the test row correctly so it doesn't break audit
                # verification for other tests sharing this database.
                last = s.query(AuditEvent).order_by(AuditEvent.seq.desc()).first()
                row.event_id, row.ts = uid(), now()
                row.action, row.outcome, row.meta = "TEST", "SUCCESS", {}
                row.prev_hash = last.hash if last else "0" * 64
                row.hash = _digest(row.prev_hash, row)
            else:  # IntegrityCheck
                user, case, ev = _seed_user_evidence(s, "icuser", "EV-IC-1", "ic-b.txt")
                row.evidence_id, row.result, row.reference, row.by_user_id = ev.id, "MATCH", "0" * 64, user.id
            s.add(row)
            s.commit()
            keys[cls] = row.id if cls is not AuditEvent else row.event_id
        return keys
    finally:
        s.close()


@pytest.fixture(scope="module")
def keys():
    return _make_rows()


def _keyed_query(s, cls, key):
    q = s.query(cls)
    col = cls.event_id if cls is AuditEvent else cls.id
    return q.filter(col == key)


def test_orm_update_blocked(client, keys):
    for cls in APPEND_ONLY:
        col = "result" if cls is IntegrityCheck else "action"
        s = SessionLocal()
        try:
            row = _keyed_query(s, cls, keys[cls]).one()
            setattr(row, col, "TAMPERED")
            with pytest.raises(PermissionError):
                s.commit()
            s.rollback()
        finally:
            s.close()


def test_orm_delete_blocked(client, keys):
    for cls in APPEND_ONLY:
        s = SessionLocal()
        try:
            row = _keyed_query(s, cls, keys[cls]).one()
            s.delete(row)
            with pytest.raises(PermissionError):
                s.commit()
            s.rollback()
        finally:
            s.close()


def test_bulk_query_update_blocked(client, keys):
    """session.query(...).update() bypasses before_update; before_flush must catch it."""
    for cls in APPEND_ONLY:
        col = "result" if cls is IntegrityCheck else "action"
        s = SessionLocal()
        try:
            with pytest.raises(PermissionError):
                _keyed_query(s, cls, keys[cls]).update({col: "TAMPERED"})
            s.rollback()
        finally:
            s.close()


def test_bulk_query_delete_blocked(client, keys):
    for cls in APPEND_ONLY:
        s = SessionLocal()
        try:
            with pytest.raises(PermissionError):
                _keyed_query(s, cls, keys[cls]).delete()
            s.rollback()
        finally:
            s.close()


def test_rows_still_present(client, keys):
    """Nothing above may have actually removed an append-only row."""
    s = SessionLocal()
    try:
        for cls in APPEND_ONLY:
            assert _keyed_query(s, cls, keys[cls]).count() == 1
    finally:
        s.close()


def test_raw_sql_update_blocked_by_trigger(client, keys):
    """The SQLite RAISE(ABORT) triggers must stop raw SQL outside the ORM."""
    with db.engine.connect() as conn:
        for cls in APPEND_ONLY:
            table = cls.__tablename__
            with pytest.raises(Exception):
                conn.exec_driver_sql(f"UPDATE {table} SET action = 'TAMPERED'")
            conn.rollback()
            with pytest.raises(Exception):
                conn.exec_driver_sql(f"DELETE FROM {table}")
            conn.rollback()
