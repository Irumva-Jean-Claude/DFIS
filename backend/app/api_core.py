"""Auth, users, cases, dashboard, audit trail and settings endpoints."""
import secrets
from datetime import timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, update, or_
from . import config
from .db import *  # noqa
from .db import now, iso
from .security import (PERMS, hash_pw, verify_pw, validate_password, make_token, current_user, current_session, require,
                       case_filter, get_case, audit, verify_audit_chain, verify_totp, new_totp_secret, totp_uri,
                       make_mfa_pending, mfa_pending_user, consume_mfa_pending, generate_recovery_codes)

auth_r = APIRouter(prefix="/auth", tags=["auth"])
users_r = APIRouter(prefix="/users", tags=["users"])
cases_r = APIRouter(prefix="/cases", tags=["cases"])
dash_r = APIRouter(prefix="/dashboard", tags=["dashboard"])
audit_r = APIRouter(prefix="/audit", tags=["audit"])
settings_r = APIRouter(prefix="/settings", tags=["settings"])


def user_out(u):
    return {"id": u.id, "username": u.username, "full_name": u.full_name, "email": u.email, "role": u.role,
            "is_active": u.is_active, "must_change_password": u.must_change_password, "mfa_enabled": u.mfa_enabled,
            "created_at": iso(u.created_at), "permissions": PERMS.get(u.role, [])}


def paginate(db, stmt, page, size):
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))
    rows = db.scalars(stmt.limit(size).offset((page - 1) * size)).all()
    return rows, total


# ---------------- auth ----------------
class Login(BaseModel):
    username: str = Field(max_length=60)
    password: str = Field(max_length=200)


@auth_r.post("/login")
def login(body: Login, request: Request, db=Depends(get_db)):
    uname = body.username.strip().lower()
    u = db.scalar(select(User).where(User.username == uname))
    ip = request.client.host if request.client else None
    if u and u.locked_until and u.locked_until > now():
        audit(db, None, "login_blocked", "user", u.id, "failure", attempted_username=uname, ip=ip)
        raise HTTPException(429, "Account temporarily locked after repeated failed logins. Try again later.")
    if not u or not u.is_active or not verify_pw(u.password_hash, body.password):
        if u:
            u.failed_attempts += 1
            if u.failed_attempts >= config.LOCK_THRESHOLD:
                u.locked_until, u.failed_attempts = now() + timedelta(minutes=config.LOCK_MINUTES), 0
            db.commit()
        audit(db, None, "login_failed", "user", u.id if u else None, "failure", attempted_username=uname, ip=ip)
        raise HTTPException(401, "Invalid credentials")
    u.failed_attempts, u.locked_until = 0, None
    db.commit()
    if u.mfa_enabled:
        pid = make_mfa_pending(u, db)
        audit(db, u, "login_mfa_challenge", "user", u.id, ip=ip)
        return {"mfa_required": True, "mfa_token": pid}
    tok = make_token(u, db)
    audit(db, u, "login", "user", u.id, ip=ip)
    return {"access_token": tok, "me": user_out(u)}


# ---------------- MFA (TOTP) ----------------
class MFAVerify(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=20)


@auth_r.post("/mfa/verify")
def mfa_verify(b: MFAVerify, request: Request, db=Depends(get_db)):
    u = mfa_pending_user(b.mfa_token, db)
    ip = request.client.host if request.client else None
    if not verify_totp(u.totp_secret, b.code):
        audit(db, u, "mfa_verify", "user", u.id, "failure", method="totp", ip=ip)
        raise HTTPException(401, "Invalid or expired verification code")
    consume_mfa_pending(b.mfa_token, db)
    tok = make_token(u, db)
    audit(db, u, "login", "user", u.id, ip=ip, mfa=True)
    return {"access_token": tok, "me": user_out(u)}


@auth_r.post("/mfa/verify-recovery")
def mfa_verify_recovery(b: MFAVerify, request: Request, db=Depends(get_db)):
    u = mfa_pending_user(b.mfa_token, db)
    ip = request.client.host if request.client else None
    code = b.code.strip().replace(" ", "").lower()
    used = None
    for rc in db.scalars(select(RecoveryCode).where(RecoveryCode.user_id == u.id, RecoveryCode.used_at.is_(None))):
        if verify_pw(rc.code_hash, code):
            used = rc
            break
    if not used:
        audit(db, u, "mfa_verify", "user", u.id, "failure", method="recovery_code", ip=ip)
        raise HTTPException(401, "Invalid recovery code")
    used.used_at = now()
    consume_mfa_pending(b.mfa_token, db)
    tok = make_token(u, db)
    audit(db, u, "login", "user", u.id, ip=ip, mfa=True, method="recovery_code")
    return {"access_token": tok, "me": user_out(u)}


@auth_r.get("/mfa/status")
def mfa_status(u=Depends(current_user)):
    return {"mfa_enabled": u.mfa_enabled}


@auth_r.post("/mfa/setup")
def mfa_setup(u=Depends(current_user), db=Depends(get_db)):
    if u.mfa_enabled:
        raise HTTPException(409, "Multi-factor authentication is already enabled")
    # reuse the pending secret so a re-opened dialog never invalidates a QR
    # that was already scanned; only generate when none is stored yet
    secret = u.totp_secret or new_totp_secret()
    u.totp_secret = secret
    db.commit()
    import base64, io as _io
    import qrcode
    uri = totp_uri(secret, u.username)
    img = qrcode.make(uri)
    buf = _io.BytesIO(); img.save(buf, format="PNG")
    audit(db, u, "mfa_setup_started", "user", u.id)
    return {"secret": secret, "otpauth_uri": uri,
            "qr_png_base64": base64.b64encode(buf.getvalue()).decode(),
            "note": "Scan with an authenticator app (Google/Microsoft Authenticator, Authy), then confirm a code to activate."}


class MFACode(BaseModel):
    code: str = Field(min_length=6, max_length=20)


@auth_r.post("/mfa/enable")
def mfa_enable(b: MFACode, su=Depends(current_session), db=Depends(get_db)):
    s, u = su
    if u.mfa_enabled:
        raise HTTPException(409, "Multi-factor authentication is already enabled")
    if not u.totp_secret or not verify_totp(u.totp_secret, b.code):
        audit(db, u, "mfa_enable", "user", u.id, "failure")
        raise HTTPException(401, "Invalid verification code - make sure your authenticator app has the CURRENT QR code (delete the old entry and rescan if you opened setup more than once), and that your device clock is correct.")
    u.mfa_enabled = True
    codes = generate_recovery_codes()
    for c in codes:
        db.add(RecoveryCode(user_id=u.id, code_hash=hash_pw(c)))
    db.commit()
    audit(db, u, "mfa_enabled", "user", u.id)
    return {"mfa_enabled": True, "recovery_codes": codes,
            "note": "Store these recovery codes securely - each works once and they are never shown again."}


@auth_r.post("/mfa/disable")
def mfa_disable(b: MFACode, su=Depends(current_session), db=Depends(get_db)):
    s, u = su
    if not verify_totp(u.totp_secret, b.code):
        audit(db, u, "mfa_disable", "user", u.id, "failure")
        raise HTTPException(401, "Invalid verification code")
    u.mfa_enabled, u.totp_secret = False, None
    db.execute(update(RecoveryCode).where(RecoveryCode.user_id == u.id, RecoveryCode.used_at.is_(None)).values(used_at=now()))
    db.commit()
    audit(db, u, "mfa_disabled", "user", u.id)
    return {"mfa_enabled": False}


@auth_r.post("/mfa/recovery-codes")
def mfa_new_recovery_codes(b: MFACode, su=Depends(current_session), db=Depends(get_db)):
    s, u = su
    if not u.mfa_enabled or not verify_totp(u.totp_secret, b.code):
        raise HTTPException(401, "Invalid verification code")
    db.execute(update(RecoveryCode).where(RecoveryCode.user_id == u.id, RecoveryCode.used_at.is_(None)).values(used_at=now()))
    codes = generate_recovery_codes()
    for c in codes:
        db.add(RecoveryCode(user_id=u.id, code_hash=hash_pw(c)))
    db.commit()
    audit(db, u, "mfa_recovery_codes_regenerated", "user", u.id)
    return {"recovery_codes": codes, "note": "Old unused codes were invalidated. Store these securely - shown once."}


@auth_r.post("/refresh")
def refresh(su=Depends(current_session), db=Depends(get_db)):
    s, u = su
    s.revoked = True
    db.commit()
    return {"access_token": make_token(u, db), "me": user_out(u)}


@auth_r.post("/logout")
def logout(su=Depends(current_session), db=Depends(get_db)):
    s, u = su
    s.revoked = True
    db.commit()
    audit(db, u, "logout", "user", u.id)
    return {"ok": True}


@auth_r.get("/me")
def me(u=Depends(current_user)):
    return user_out(u)


class PwChange(BaseModel):
    current_password: str
    new_password: str = Field(max_length=200)


@auth_r.post("/change-password")
def change_password(b: PwChange, su=Depends(current_session), db=Depends(get_db)):
    s, u = su
    if not verify_pw(u.password_hash, b.current_password):
        audit(db, u, "password_change", "user", u.id, "failure")
        raise HTTPException(400, "Current password is incorrect")
    validate_password(b.new_password)
    u.password_hash, u.must_change_password = hash_pw(b.new_password), False
    db.execute(update(UserSession).where(UserSession.user_id == u.id, UserSession.id != s.id).values(revoked=True))
    db.commit()
    audit(db, u, "password_change", "user", u.id)
    return {"ok": True}


# ---------------- users ----------------
class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9_.-]+$")
    full_name: str = Field(min_length=1, max_length=100)
    email: str = Field(default="", max_length=150, pattern=r"^[^@\s]*@?[^@\s]*$")
    role: str
    password: str = Field(max_length=200)


class UserPatch(BaseModel):
    full_name: Optional[str] = Field(default=None, max_length=100)
    role: Optional[str] = None
    is_active: Optional[bool] = None


@users_r.get("/directory")
def directory(u=Depends(current_user), db=Depends(get_db)):
    rows = db.scalars(select(User).where(User.is_active == True).order_by(User.full_name)).all()  # noqa
    return [{"id": x.id, "username": x.username, "full_name": x.full_name, "role": x.role} for x in rows]


@users_r.get("")
def list_users(admin=Depends(require("users:manage")), db=Depends(get_db)):
    return [user_out(x) for x in db.scalars(select(User).order_by(User.created_at))]


@users_r.post("", status_code=201)
def create_user(b: UserCreate, admin=Depends(require("users:manage")), db=Depends(get_db)):
    if b.role not in PERMS:
        raise HTTPException(422, f"Role must be one of {list(PERMS)}")
    validate_password(b.password)
    if db.scalar(select(User).where(User.username == b.username.lower())):
        raise HTTPException(409, "Username already exists")
    u = User(username=b.username.lower(), full_name=b.full_name, email=b.email, role=b.role,
             password_hash=hash_pw(b.password), must_change_password=True)
    db.add(u); db.commit()
    audit(db, admin, "user_created", "user", u.id, role=b.role)
    return user_out(u)


@users_r.patch("/{uid_}")
def patch_user(uid_: str, b: UserPatch, admin=Depends(require("users:manage")), db=Depends(get_db)):
    u = db.get(User, uid_)
    if not u:
        raise HTTPException(404, "User not found")
    if u.id == admin.id and (b.is_active is False or (b.role and b.role != "admin")):
        raise HTTPException(400, "Administrators cannot demote or deactivate themselves")
    if b.role is not None:
        if b.role not in PERMS:
            raise HTTPException(422, "Invalid role")
        audit(db, admin, "role_changed", "user", u.id, old=u.role, new=b.role)
        u.role = b.role
    if b.full_name:
        u.full_name = b.full_name
    if b.is_active is not None:
        u.is_active = b.is_active
        if not b.is_active:
            db.execute(update(UserSession).where(UserSession.user_id == u.id).values(revoked=True))
        audit(db, admin, "user_activated" if b.is_active else "user_deactivated", "user", u.id)
    db.commit()
    return user_out(u)


@users_r.post("/{uid_}/reset-password")
def reset_password(uid_: str, admin=Depends(require("users:manage")), db=Depends(get_db)):
    u = db.get(User, uid_)
    if not u:
        raise HTTPException(404, "User not found")
    temp = secrets.token_urlsafe(12) + "7a"
    u.password_hash, u.must_change_password, u.failed_attempts, u.locked_until = hash_pw(temp), True, 0, None
    db.execute(update(UserSession).where(UserSession.user_id == u.id).values(revoked=True))
    db.commit()
    audit(db, admin, "password_reset", "user", u.id)
    return {"temporary_password": temp, "note": "Shown once. User must change it at next login."}


# ---------------- cases ----------------
STATUS_FLOW = {"open": {"active", "closed"}, "active": {"closed"}, "closed": {"active", "archived"}, "archived": set()}


class CaseIn(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=5000)
    category: str = Field(default="general", max_length=60)
    priority: str = Field(default="medium", pattern="^(low|medium|high|critical)$")


class CasePatch(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=200)
    description: Optional[str] = Field(default=None, max_length=5000)
    category: Optional[str] = Field(default=None, max_length=60)
    priority: Optional[str] = Field(default=None, pattern="^(low|medium|high|critical)$")
    status: Optional[str] = Field(default=None, pattern="^(open|active|closed|archived)$")


def case_out(db, c):
    inv = db.execute(select(User.id, User.full_name).join(CaseAssignment, CaseAssignment.user_id == User.id)
                     .where(CaseAssignment.case_id == c.id)).all()
    return {"id": c.id, "ref": c.ref, "title": c.title, "description": c.description, "category": c.category,
            "priority": c.priority, "status": c.status, "created_at": iso(c.created_at), "updated_at": iso(c.updated_at),
            "archived_at": iso(c.archived_at), "retention_until": iso(c.retention_until),
            "investigators": [{"id": i, "name": n} for i, n in inv],
            "evidence_count": db.scalar(select(func.count(Evidence.id)).where(Evidence.case_id == c.id))}


@cases_r.post("", status_code=201)
def create_case(b: CaseIn, u=Depends(require("case:create")), db=Depends(get_db)):
    n = db.scalar(select(func.count(Case.id))) + 1
    while db.scalar(select(Case.id).where(Case.ref == f"DFIS-{now().year}-{n:04d}")):
        n += 1
    c = Case(ref=f"DFIS-{now().year}-{n:04d}", created_by=u.id, **b.model_dump())
    db.add(c); db.flush()
    db.add(CaseAssignment(case_id=c.id, user_id=u.id)); db.commit()
    audit(db, u, "case_created", "case", c.id, ref=c.ref)
    return case_out(db, c)


@cases_r.get("")
def list_cases(u=Depends(require("case:read")), db=Depends(get_db), q: str = "", status: str = "", priority: str = "",
               sort: str = "created_at", order: str = "desc", page: int = Query(1, ge=1), size: int = Query(10, ge=1, le=100)):
    st = select(Case).where(case_filter(u))
    if q:
        st = st.where(or_(Case.title.ilike(f"%{q}%"), Case.ref.ilike(f"%{q}%")))
    if status:
        st = st.where(Case.status == status)
    if priority:
        st = st.where(Case.priority == priority)
    col = {"created_at": Case.created_at, "title": Case.title, "priority": Case.priority, "status": Case.status}.get(sort, Case.created_at)
    rows, total = paginate(db, st.order_by(col.asc() if order == "asc" else col.desc()), page, size)
    return {"items": [case_out(db, c) for c in rows], "total": total, "page": page, "size": size}


@cases_r.get("/{cid}")
def get_one(cid: str, u=Depends(require("case:read")), db=Depends(get_db)):
    return case_out(db, get_case(db, u, cid))


@cases_r.patch("/{cid}")
def patch_case(cid: str, b: CasePatch, u=Depends(require("case:edit")), db=Depends(get_db)):
    c = get_case(db, u, cid)
    data = b.model_dump(exclude_none=True)
    st = data.pop("status", None)
    if st and st != c.status:
        if st not in STATUS_FLOW[c.status]:
            raise HTTPException(409, f"Cannot move case from '{c.status}' to '{st}'")
        if st == "archived":
            c.archived_at = now()
            c.retention_until = now() + timedelta(days=config.RETENTION_DAYS)
        audit(db, u, "case_status_changed", "case", c.id, old=c.status, new=st)
        c.status = st
    for k, v in data.items():
        setattr(c, k, v)
    db.commit()
    audit(db, u, "case_updated", "case", c.id, fields=list(data))
    return case_out(db, c)


class Assign(BaseModel):
    user_id: str


@cases_r.post("/{cid}/assign")
def assign(cid: str, b: Assign, u=Depends(require("case:assign")), db=Depends(get_db)):
    c = get_case(db, u, cid)
    if not db.get(User, b.user_id):
        raise HTTPException(404, "User not found")
    if not db.scalar(select(CaseAssignment.id).where(CaseAssignment.case_id == c.id, CaseAssignment.user_id == b.user_id)):
        db.add(CaseAssignment(case_id=c.id, user_id=b.user_id)); db.commit()
        audit(db, u, "case_assigned", "case", c.id, assignee=b.user_id)
    return case_out(db, c)


@cases_r.delete("/{cid}/assign/{user_id}")
def unassign(cid: str, user_id: str, u=Depends(require("case:assign")), db=Depends(get_db)):
    c = get_case(db, u, cid)
    a = db.scalar(select(CaseAssignment).where(CaseAssignment.case_id == c.id, CaseAssignment.user_id == user_id))
    if a:
        db.delete(a); db.commit()
        audit(db, u, "case_unassigned", "case", c.id, assignee=user_id)
    return case_out(db, c)


@cases_r.get("/{cid}/history")
def history(cid: str, u=Depends(require("case:read")), db=Depends(get_db)):
    c = get_case(db, u, cid)
    rows = db.scalars(select(AuditEvent).where(AuditEvent.object_type == "case", AuditEvent.object_id == c.id)
                      .order_by(AuditEvent.seq.desc()).limit(100))
    return [{"ts": iso(r.ts), "actor": r.actor_name, "action": r.action, "meta": r.meta} for r in rows]


# ---------------- dashboard ----------------
@dash_r.get("")
def dashboard(u=Depends(current_user), db=Depends(get_db)):
    cf = case_filter(u)
    ids = select(Case.id).where(cf)
    by_status = dict(db.execute(select(Case.status, func.count()).where(cf).group_by(Case.status)).all())
    ev_types = db.execute(select(Evidence.evidence_type, func.count()).where(Evidence.case_id.in_(ids))
                          .group_by(Evidence.evidence_type)).all()
    an = db.execute(select(AnalysisResult.status, func.count()).join(Evidence, Evidence.id == AnalysisResult.evidence_id)
                    .where(Evidence.case_id.in_(ids)).group_by(AnalysisResult.status)).all()
    ics = db.execute(select(IntegrityCheck, Evidence.ref).join(Evidence, Evidence.id == IntegrityCheck.evidence_id)
                     .where(Evidence.case_id.in_(ids)).order_by(IntegrityCheck.created_at.desc()).limit(6)).all()
    acked = select(CustodyEvent.ref_event_id).where(CustodyEvent.action == "ACKNOWLEDGED")
    pend = db.execute(select(CustodyEvent, Evidence.ref).join(Evidence, Evidence.id == CustodyEvent.evidence_id)
                      .where(CustodyEvent.case_id.in_(ids), CustodyEvent.action == "TRANSFER",
                             CustodyEvent.id.not_in(acked)).order_by(CustodyEvent.created_at.desc()).limit(8)).all()
    astmt = select(AuditEvent).order_by(AuditEvent.seq.desc())
    if "audit:read" not in PERMS[u.role]:
        astmt = astmt.where(AuditEvent.actor_id == u.id)
    recent = db.scalars(astmt.limit(8)).all()
    since = now() - timedelta(days=13)
    day = {}
    for a in db.scalars(astmt.where(AuditEvent.ts >= since).limit(5000)):
        day[a.ts.date().isoformat()] = day.get(a.ts.date().isoformat(), 0) + 1
    activity = [{"label": (since + timedelta(days=i)).date().isoformat()[5:], "value": day.get((since + timedelta(days=i)).date().isoformat(), 0)} for i in range(14)]
    return {"cases": {"total": sum(by_status.values()), **{k: by_status.get(k, 0) for k in ("open", "active", "closed", "archived")}},
            "evidence_total": sum(v for _, v in ev_types), "evidence_by_type": [{"label": t, "value": v} for t, v in ev_types],
            "analysis": [{"label": s, "value": v} for s, v in an], "activity": activity,
            "recent_integrity": [{"evidence": r, "result": i.result, "at": iso(i.created_at)} for i, r in ics],
            "pending_custody": [{"evidence": r, "evidence_id": c.evidence_id, "at": iso(c.created_at)} for c, r in pend],
            "recent_audit": [{"ts": iso(a.ts), "actor": a.actor_name, "action": a.action, "outcome": a.outcome} for a in recent]}


# ---------------- audit ----------------
@audit_r.get("")
def list_audit(u=Depends(current_user), db=Depends(get_db), action: str = "", q: str = "",
               page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=100)):
    st = select(AuditEvent).order_by(AuditEvent.seq.desc())
    if u.role not in ("admin", "lead"):
        st = st.where(AuditEvent.actor_id == u.id)
    if action:
        st = st.where(AuditEvent.action == action)
    if q:
        st = st.where(or_(AuditEvent.actor_name.ilike(f"%{q}%"), AuditEvent.action.ilike(f"%{q}%")))
    rows, total = paginate(db, st, page, size)
    return {"items": [{"seq": r.seq, "event_id": r.event_id, "ts": iso(r.ts), "actor": r.actor_name, "action": r.action,
                       "object_type": r.object_type, "object_id": r.object_id, "outcome": r.outcome, "meta": r.meta} for r in rows],
            "total": total, "page": page, "size": size}


@audit_r.get("/verify")
def verify(u=Depends(require("users:manage")), db=Depends(get_db)):
    return verify_audit_chain(db)


# ---------------- settings ----------------
@settings_r.get("")
def get_settings(u=Depends(require("settings:manage")), db=Depends(get_db)):
    from .forensic import DEFAULT_RULES
    r = db.get(SystemConfig, "log_rules")
    return {"notice": "Prototype for academic use. Not forensically certified, legally validated or court-ready.",
            "max_upload_mb": config.MAX_UPLOAD_BYTES // 1048576, "allowed_extensions": sorted(config.ALLOWED_EXT),
            "retention_days": config.RETENTION_DAYS, "access_token_minutes": config.ACCESS_TOKEN_MINUTES,
            "database": config.DATABASE_URL.split(":")[0], "log_rules": {**DEFAULT_RULES, **(r.value if r else {})}}


class Rules(BaseModel):
    auth_failure_threshold: int = Field(ge=2, le=1000)
    window_minutes: int = Field(ge=1, le=1440)
    privilege_keywords: list[str] = Field(max_length=50)
    custom_keywords: list[str] = Field(default=[], max_length=50)


@settings_r.put("/log_rules")
def put_rules(b: Rules, u=Depends(require("settings:manage")), db=Depends(get_db)):
    row = db.get(SystemConfig, "log_rules") or SystemConfig(key="log_rules", value={})
    row.value = b.model_dump()
    db.merge(row); db.commit()
    audit(db, u, "settings_changed", "settings", "log_rules")
    return row.value
