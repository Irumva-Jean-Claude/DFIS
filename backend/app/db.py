"""Database engine and ORM models. Audit/custody/integrity tables are append-only at ORM level."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (create_engine, event, text, String, Integer, Boolean, DateTime, Text, JSON, ForeignKey,
                        UniqueConstraint, Index)
from sqlalchemy.engine import make_url
from typing import Annotated
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from . import config

def uid() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    """Naive UTC timestamp, used everywhere in the schema."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(d: datetime | None) -> str | None:
    """Format a datetime as an ISO-8601 string with a Z suffix, or None."""
    return (d.isoformat(timespec="seconds") + "Z") if d else None

# Compare the parsed dialect name instead of string prefix matching, so
# "sqlite+driver://..." still gets the arg and "SQLite://"-style variants don't
# accidentally match the wrong dialect.
_db_url = make_url(config.DATABASE_URL)
engine = create_engine(config.DATABASE_URL, pool_pre_ping=True,
                       connect_args={"check_same_thread": False} if _db_url.get_driver_name() == "sqlite" else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


PkStr = Annotated[str, mapped_column(String(36), primary_key=True, default=uid)]
"""Declarative UUID-string primary key: `id: PkStr`"""


def _fk_str(target: str, **kw):
    """Build a ForeignKey column; used by the FkStr annotation factory below."""
    return mapped_column(String(36), ForeignKey(target), **kw)


class FkStr:
    """Declarative UUID-string foreign key: `user_id: FkStr["users.id"]`.

    Subscript it with the target column; extra kwargs (index=True,
    nullable=True, ...) are forwarded to mapped_column.
    """

    def __class_getitem__(cls, key):
        target, kw = (key, {}) if not isinstance(key, tuple) else (key[0], key[1])
        return Annotated[str, _fk_str(target, **kw)]


class User(Base):
    __tablename__ = "users"
    id: Mapped[PkStr]
    username = mapped_column(String(40), unique=True, index=True)
    full_name = mapped_column(String(100))
    email = mapped_column(String(150), default="")
    password_hash = mapped_column(String(255))
    role = mapped_column(String(20))
    is_active = mapped_column(Boolean, default=True)
    failed_attempts = mapped_column(Integer, default=0)
    locked_until = mapped_column(DateTime, nullable=True)
    must_change_password = mapped_column(Boolean, default=False)
    totp_secret = mapped_column(String(64), nullable=True)   # set on enrollment, confirmed before use
    mfa_enabled = mapped_column(Boolean, default=False)
    created_at = mapped_column(DateTime, default=now)


class UserSession(Base):
    __tablename__ = "sessions"
    id: Mapped[PkStr]  # JWT jti
    user_id: Mapped[FkStr["users.id", dict(index=True)]]
    expires_at = mapped_column(DateTime)
    revoked = mapped_column(Boolean, default=False)
    created_at = mapped_column(DateTime, default=now)


class RecoveryCode(Base):  # single-use MFA backup codes
    __tablename__ = "recovery_codes"
    id: Mapped[PkStr]
    user_id: Mapped[FkStr["users.id", dict(index=True)]]
    code_hash = mapped_column(String(255))
    used_at = mapped_column(DateTime, nullable=True)
    created_at = mapped_column(DateTime, default=now)


class MFAPending(Base):  # short-lived challenge between password and second factor
    __tablename__ = "mfa_pending"
    id = mapped_column(String(36), primary_key=True)
    user_id: Mapped[FkStr["users.id", dict(index=True)]]
    expires_at = mapped_column(DateTime)
    created_at = mapped_column(DateTime, default=now)


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[PkStr]
    ref = mapped_column(String(30), unique=True, index=True)
    title = mapped_column(String(200))
    description = mapped_column(Text, default="")
    category = mapped_column(String(60), default="general")
    priority = mapped_column(String(10), default="medium")
    status = mapped_column(String(10), default="open", index=True)
    created_by: Mapped[FkStr["users.id"]]
    created_at = mapped_column(DateTime, default=now)
    updated_at = mapped_column(DateTime, default=now, onupdate=now)
    archived_at = mapped_column(DateTime, nullable=True)
    retention_until = mapped_column(DateTime, nullable=True)


class CaseAssignment(Base):
    __tablename__ = "case_assignments"
    __table_args__ = (UniqueConstraint("case_id", "user_id"),)
    id: Mapped[PkStr]
    case_id: Mapped[FkStr["cases.id", dict(index=True)]]
    user_id: Mapped[FkStr["users.id", dict(index=True)]]
    assigned_at = mapped_column(DateTime, default=now)


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[PkStr]
    ref = mapped_column(String(30), unique=True, index=True)
    case_id: Mapped[FkStr["cases.id", dict(index=True)]]
    evidence_type = mapped_column(String(20))
    original_filename = mapped_column(String(200))
    description = mapped_column(Text, default="")
    source = mapped_column(String(200))
    acquisition_method = mapped_column(String(200))
    acquisition_raw = mapped_column(String(60), nullable=True)
    acquisition_utc = mapped_column(DateTime, nullable=True)
    acquisition_note = mapped_column(String(200), nullable=True)
    submitted_by = mapped_column(String(100))
    received_by = mapped_column(String(100))
    mime = mapped_column(String(100))
    size = mapped_column(Integer)
    sha256 = mapped_column(String(64))
    hashed_at = mapped_column(DateTime)
    storage_name = mapped_column(String(64), unique=True)  # internal only, never exposed
    status = mapped_column(String(20), default="in_custody")
    custodian_id: Mapped[FkStr["users.id", dict(nullable=True)]]
    uploaded_by: Mapped[FkStr["users.id"]]
    created_at = mapped_column(DateTime, default=now)
    vt_status = mapped_column(String(20), nullable=True)
    vt_malicious = mapped_column(Integer, nullable=True)
    vt_suspicious = mapped_column(Integer, nullable=True)
    vt_total_engines = mapped_column(Integer, nullable=True)
    vt_message = mapped_column(Text, nullable=True)
    vt_scanned_at = mapped_column(DateTime, nullable=True)


class CustodyEvent(Base):  # append-only
    __tablename__ = "custody_events"
    id: Mapped[PkStr]
    evidence_id: Mapped[FkStr["evidence.id", dict(index=True)]]
    case_id: Mapped[FkStr["cases.id"]]
    action = mapped_column(String(30))  # INGESTED / TRANSFER / ACKNOWLEDGED / TRANSFER_CANCELLED / CORRECTION_NOTE
    from_user_id: Mapped[FkStr["users.id", dict(nullable=True)]]
    to_user_id: Mapped[FkStr["users.id", dict(nullable=True)]]
    by_user_id: Mapped[FkStr["users.id"]]
    reason = mapped_column(Text, default="")
    notes = mapped_column(Text, default="")
    ref_event_id = mapped_column(String(36), nullable=True, index=True)
    created_at = mapped_column(DateTime, default=now)


class IntegrityCheck(Base):  # append-only
    __tablename__ = "integrity_checks"
    id: Mapped[PkStr]
    evidence_id: Mapped[FkStr["evidence.id", dict(index=True)]]
    result = mapped_column(String(12))  # MATCH / MISMATCH / ERROR
    calculated = mapped_column(String(64), nullable=True)
    reference = mapped_column(String(64))
    by_user_id: Mapped[FkStr["users.id"]]
    created_at = mapped_column(DateTime, default=now)


class AnalysisResult(Base):
    __tablename__ = "analysis_results"
    id: Mapped[PkStr]
    evidence_id: Mapped[FkStr["evidence.id", dict(index=True)]]
    kind = mapped_column(String(10))  # file / log
    status = mapped_column(String(12), default="running")
    result = mapped_column(JSON, nullable=True)
    error = mapped_column(Text, nullable=True)
    by_user_id: Mapped[FkStr["users.id"]]
    created_at = mapped_column(DateTime, default=now)
    finished_at = mapped_column(DateTime, nullable=True)


class LogEvent(Base):
    __tablename__ = "log_events"
    __table_args__ = (Index("ix_log_ev_ts", "evidence_id", "ts_utc"),)
    id: Mapped[PkStr]
    evidence_id: Mapped[FkStr["evidence.id"]]
    line_no = mapped_column(Integer)
    ts_utc = mapped_column(DateTime, nullable=True)
    ts_original = mapped_column(String(80), nullable=True)
    ts_note = mapped_column(String(200), nullable=True)
    event_type = mapped_column(String(30), index=True)
    source = mapped_column(String(120), nullable=True)
    username = mapped_column(String(80), nullable=True)
    message = mapped_column(Text)


class TimelineEvent(Base):
    __tablename__ = "timeline_events"
    id: Mapped[PkStr]
    case_id: Mapped[FkStr["cases.id", dict(index=True)]]
    evidence_id: Mapped[FkStr["evidence.id", dict(nullable=True)]]
    kind = mapped_column(String(10))  # analyst / metadata
    title = mapped_column(String(200))
    details = mapped_column(Text, default="")
    original_ts = mapped_column(String(80), nullable=True)
    utc = mapped_column(DateTime, nullable=True)
    note = mapped_column(String(300), nullable=True)
    created_by: Mapped[FkStr["users.id"]]
    created_at = mapped_column(DateTime, default=now)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[PkStr]
    ref = mapped_column(String(30), unique=True)
    case_id: Mapped[FkStr["cases.id", dict(index=True)]]
    version = mapped_column(Integer)
    filename = mapped_column(String(64))
    by_user_id: Mapped[FkStr["users.id"]]
    created_at = mapped_column(DateTime, default=now)
    # Integrity seal: SHA-256 of the issued PDF and an HMAC-SHA256 signature over it.
    sha256 = mapped_column(String(64), nullable=True, index=True)
    signature = mapped_column(String(64), nullable=True)
    signed_at = mapped_column(DateTime, nullable=True)


class AuditEvent(Base):  # append-only, hash-chained
    __tablename__ = "audit_events"
    seq = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id = mapped_column(String(36), unique=True, default=uid)
    ts = mapped_column(DateTime, default=now)
    actor_id = mapped_column(String(36), nullable=True, index=True)
    actor_name = mapped_column(String(60), nullable=True)
    action = mapped_column(String(60), index=True)
    object_type = mapped_column(String(30), nullable=True)
    object_id = mapped_column(String(36), nullable=True, index=True)
    outcome = mapped_column(String(12))
    meta = mapped_column(JSON, nullable=True)
    prev_hash = mapped_column(String(64))
    hash = mapped_column(String(64))


class SystemConfig(Base):
    __tablename__ = "system_config"
    key = mapped_column(String(60), primary_key=True)
    value = mapped_column(JSON)


APPEND_ONLY_TABLES = {"audit_events", "custody_events", "integrity_checks"}
_APPEND_ONLY_CLASSES = (AuditEvent, CustodyEvent, IntegrityCheck)


def _block(*a):
    raise PermissionError("This record type is append-only and cannot be modified or deleted.")


def _validate_custody_event(mapper, connection, target):
    """Guard the custody chain: the event's case must match the evidence's case."""
    if target.evidence_id is None or target.case_id is None:
        raise PermissionError("CustodyEvent requires both evidence_id and case_id.")
    row = connection.execute(
        text("SELECT case_id FROM evidence WHERE id = :eid"),
        {"eid": target.evidence_id},
    ).first()
    if row is None:
        raise PermissionError(
            f"CustodyEvent references unknown evidence_id {target.evidence_id}.")
    if row[0] != target.case_id:
        raise PermissionError(
            "CustodyEvent case_id does not match the evidence's case; "
            "custody chain would be corrupted.")


for _cls in _APPEND_ONLY_CLASSES:
    event.listen(_cls, "before_update", _block)
    event.listen(_cls, "before_delete", _block)


def _before_flush(session, flush_context, instances):
    """Catch UPDATE/DELETE flushes of append-only tables (incl. bulk Query DML)."""
    tainted = [m.local_table.name for m in flush_context.mappers
               if m.local_table.name in APPEND_ONLY_TABLES]
    if tainted:
        raise PermissionError(
            "This record type is append-only and cannot be modified or deleted: "
            + ", ".join(sorted(set(tainted))))


event.listen(SessionLocal, "before_flush", _before_flush)


def _block_orm_execute(execute_state):
    """Bulk Query.update()/delete() skip the unit of work; intercept at execution."""
    if not (execute_state.is_update or execute_state.is_delete):
        return
    tables = set()
    for entity in execute_state.all_mappers:
        if entity.local_table.name in APPEND_ONLY_TABLES:
            tables.add(entity.local_table.name)
    if tables:
        raise PermissionError(
            "This record type is append-only and cannot be modified or deleted: "
            + ", ".join(sorted(tables)))


event.listen(SessionLocal, "do_orm_execute", _block_orm_execute)

event.listen(CustodyEvent, "before_insert", _validate_custody_event)


_TRIGGER_SQL = """
CREATE TRIGGER IF NOT EXISTS {name}_no_update BEFORE UPDATE ON {table}
BEGIN
    SELECT RAISE(ABORT, 'This record type is append-only and cannot be modified or deleted.');
END;
CREATE TRIGGER IF NOT EXISTS {name}_no_delete BEFORE DELETE ON {table}
BEGIN
    SELECT RAISE(ABORT, 'This record type is append-only and cannot be modified or deleted.');
END;
"""


def _install_db_triggers(dbapi_conn, record):
    """Create SQLite RAISE(ABORT) triggers so raw SQL bulk DML also fails.

    Skipped silently if the tables don't exist yet (they are created by
    Base.metadata.create_all on first startup); IF NOT EXISTS makes re-runs
    idempotent once the schema is present.
    """
    cur = dbapi_conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    existing = {r[0] for r in cur.fetchall()}
    for table in APPEND_ONLY_TABLES:
        if table not in existing:
            continue
        cur.executescript(_TRIGGER_SQL.format(name=table, table=table))
    cur.close()


_PG_TRIGGER_SQL = """
CREATE OR REPLACE FUNCTION append_only_guard() RETURNS trigger AS $func$
BEGIN
    RAISE EXCEPTION 'This record type is append-only and cannot be modified or deleted.';
END;
$func$ LANGUAGE plpgsql;
CREATE TRIGGER {name}_no_update BEFORE UPDATE ON {table}
    FOR EACH ROW EXECUTE FUNCTION append_only_guard();
CREATE TRIGGER {name}_no_delete BEFORE DELETE ON {table}
    FOR EACH ROW EXECUTE FUNCTION append_only_guard();
"""


def _install_pg_triggers(dbapi_conn, record):
    """Create PostgreSQL trigger functions so raw SQL bulk DML also fails."""
    cur = dbapi_conn.cursor()
    for table in APPEND_ONLY_TABLES:
        cur.execute("SELECT 1 FROM pg_trigger WHERE tgname = %s", (f"{table}_no_update",))
        if cur.fetchone() is None:
            cur.execute(_PG_TRIGGER_SQL.format(name=table, table=table))
    cur.close()


_dialect = engine.dialect.name
if _dialect == "sqlite":
    event.listen(engine, "connect", _install_db_triggers)


def _ensure_triggers_after_create(bind=None):
    """Install RAISE triggers right after tables are created (first startup)."""
    if _dialect not in ("sqlite", "postgresql"):
        return
    conn = bind.connect() if bind is not None else engine.connect()
    try:
        dbapi = conn.connection.dbapi_connection
        if _dialect == "sqlite":
            _install_db_triggers(dbapi, None)
        else:
            _install_pg_triggers(dbapi, None)
    finally:
        conn.close()
