"""Database engine and ORM models. Audit/custody/integrity tables are append-only at ORM level."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (create_engine, event, String, Integer, Boolean, DateTime, Text, JSON, ForeignKey,
                        UniqueConstraint, Index)
from sqlalchemy.orm import DeclarativeBase, mapped_column, sessionmaker
from . import config

uid = lambda: str(uuid.uuid4())
now = lambda: datetime.now(timezone.utc).replace(tzinfo=None)  # naive UTC everywhere
iso = lambda d: (d.isoformat(timespec="seconds") + "Z") if d else None

engine = create_engine(config.DATABASE_URL, pool_pre_ping=True,
                       connect_args={"check_same_thread": False} if config.DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def pk():
    return mapped_column(String(36), primary_key=True, default=uid)


def fk(t, **kw):
    return mapped_column(String(36), ForeignKey(t), **kw)


class User(Base):
    __tablename__ = "users"
    id = pk()
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
    id = pk()  # JWT jti
    user_id = fk("users.id", index=True)
    expires_at = mapped_column(DateTime)
    revoked = mapped_column(Boolean, default=False)
    created_at = mapped_column(DateTime, default=now)


class RecoveryCode(Base):  # single-use MFA backup codes
    __tablename__ = "recovery_codes"
    id = pk()
    user_id = fk("users.id", index=True)
    code_hash = mapped_column(String(255))
    used_at = mapped_column(DateTime, nullable=True)
    created_at = mapped_column(DateTime, default=now)


class MFAPending(Base):  # short-lived challenge between password and second factor
    __tablename__ = "mfa_pending"
    id = mapped_column(String(36), primary_key=True)
    user_id = fk("users.id", index=True)
    expires_at = mapped_column(DateTime)
    created_at = mapped_column(DateTime, default=now)


class Case(Base):
    __tablename__ = "cases"
    id = pk()
    ref = mapped_column(String(30), unique=True, index=True)
    title = mapped_column(String(200))
    description = mapped_column(Text, default="")
    category = mapped_column(String(60), default="general")
    priority = mapped_column(String(10), default="medium")
    status = mapped_column(String(10), default="open", index=True)
    created_by = fk("users.id")
    created_at = mapped_column(DateTime, default=now)
    updated_at = mapped_column(DateTime, default=now, onupdate=now)
    archived_at = mapped_column(DateTime, nullable=True)
    retention_until = mapped_column(DateTime, nullable=True)


class CaseAssignment(Base):
    __tablename__ = "case_assignments"
    __table_args__ = (UniqueConstraint("case_id", "user_id"),)
    id = pk()
    case_id = fk("cases.id", index=True)
    user_id = fk("users.id", index=True)
    assigned_at = mapped_column(DateTime, default=now)


class Evidence(Base):
    __tablename__ = "evidence"
    id = pk()
    ref = mapped_column(String(30), unique=True, index=True)
    case_id = fk("cases.id", index=True)
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
    custodian_id = fk("users.id", nullable=True)
    uploaded_by = fk("users.id")
    created_at = mapped_column(DateTime, default=now)


class CustodyEvent(Base):  # append-only
    __tablename__ = "custody_events"
    id = pk()
    evidence_id = fk("evidence.id", index=True)
    case_id = fk("cases.id")
    action = mapped_column(String(30))  # INGESTED / TRANSFER / ACKNOWLEDGED / CORRECTION_NOTE
    from_user_id = fk("users.id", nullable=True)
    to_user_id = fk("users.id", nullable=True)
    by_user_id = fk("users.id")
    reason = mapped_column(Text, default="")
    notes = mapped_column(Text, default="")
    ref_event_id = mapped_column(String(36), nullable=True, index=True)
    created_at = mapped_column(DateTime, default=now)


class IntegrityCheck(Base):  # append-only
    __tablename__ = "integrity_checks"
    id = pk()
    evidence_id = fk("evidence.id", index=True)
    result = mapped_column(String(12))  # MATCH / MISMATCH / ERROR
    calculated = mapped_column(String(64), nullable=True)
    reference = mapped_column(String(64))
    by_user_id = fk("users.id")
    created_at = mapped_column(DateTime, default=now)


class AnalysisResult(Base):
    __tablename__ = "analysis_results"
    id = pk()
    evidence_id = fk("evidence.id", index=True)
    kind = mapped_column(String(10))  # file / log
    status = mapped_column(String(12), default="running")
    result = mapped_column(JSON, nullable=True)
    error = mapped_column(Text, nullable=True)
    by_user_id = fk("users.id")
    created_at = mapped_column(DateTime, default=now)
    finished_at = mapped_column(DateTime, nullable=True)


class LogEvent(Base):
    __tablename__ = "log_events"
    __table_args__ = (Index("ix_log_ev_ts", "evidence_id", "ts_utc"),)
    id = pk()
    evidence_id = fk("evidence.id")
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
    id = pk()
    case_id = fk("cases.id", index=True)
    evidence_id = fk("evidence.id", nullable=True)
    kind = mapped_column(String(10))  # analyst / metadata
    title = mapped_column(String(200))
    details = mapped_column(Text, default="")
    original_ts = mapped_column(String(80), nullable=True)
    utc = mapped_column(DateTime, nullable=True)
    note = mapped_column(String(300), nullable=True)
    created_by = fk("users.id")
    created_at = mapped_column(DateTime, default=now)


class Report(Base):
    __tablename__ = "reports"
    id = pk()
    ref = mapped_column(String(30), unique=True)
    case_id = fk("cases.id", index=True)
    version = mapped_column(Integer)
    filename = mapped_column(String(64))
    by_user_id = fk("users.id")
    created_at = mapped_column(DateTime, default=now)


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


def _block(*a):
    raise PermissionError("This record type is append-only and cannot be modified or deleted.")


for _cls in (AuditEvent, CustodyEvent, IntegrityCheck):
    event.listen(_cls, "before_update", _block)
    event.listen(_cls, "before_delete", _block)
