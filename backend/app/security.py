"""Authentication, RBAC, case-level access control and the hash-chained audit trail."""
import hashlib, json, re, secrets
from datetime import timedelta
import jwt
import pyotp
from argon2 import PasswordHasher
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy import select, or_, true
from . import config
from .db import get_db, now, User, UserSession, MFAPending, RecoveryCode, Case, CaseAssignment, Evidence, AuditEvent

_ph = PasswordHasher()
hash_pw = _ph.hash


def verify_pw(h, p):
    try:
        return _ph.verify(h, p)
    except Exception:
        return False


def validate_password(p):
    if len(p) < 10 or not re.search(r"[A-Za-z]", p) or not re.search(r"\d", p):
        raise HTTPException(422, "Password must be at least 10 characters and contain letters and digits.")


MFA_ISSUER = config.ORG_NAME
MFA_PENDING_MINUTES = 5


def new_totp_secret():
    return pyotp.random_base32()


def totp_uri(secret, username):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=MFA_ISSUER)


def verify_totp(secret, code):
    return bool(secret and code and pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1))


def make_mfa_pending(user, db):
    import uuid
    p = MFAPending(id=str(uuid.uuid4()), user_id=user.id,
                   expires_at=now() + timedelta(minutes=MFA_PENDING_MINUTES))
    db.add(p); db.commit()
    return p.id


def mfa_pending_user(pid, db):
    """Resolve an MFA challenge token; raises if invalid/expired."""
    p = db.get(MFAPending, pid)
    if not p or p.expires_at < now():
        raise HTTPException(401, "MFA challenge expired - sign in again")
    u = db.get(User, p.user_id)
    if not u or not u.is_active:
        raise HTTPException(401, "Session is no longer valid")
    return u


def consume_mfa_pending(pid, db):
    p = db.get(MFAPending, pid)
    if p:
        db.delete(p); db.commit()


def generate_recovery_codes(n=8):
    return [secrets.token_hex(5) for _ in range(n)]  # 10 hex chars each, e.g. 1a2b3c4d5e


_ALL = ["case:read", "case:create", "case:edit", "case:assign", "evidence:read", "evidence:upload", "custody:transfer",
        "analysis:run", "timeline:write", "report:create", "report:read", "audit:read", "users:manage", "settings:manage"]
PERMS = {
    "admin": _ALL,
    "lead": [p for p in _ALL if p not in ("users:manage", "settings:manage")],
    "analyst": ["case:read", "evidence:read", "analysis:run", "timeline:write", "report:read"],
    "custodian": ["case:read", "evidence:read", "evidence:upload", "custody:transfer"],
    "reviewer": ["case:read", "evidence:read", "report:read"],
}


def make_token(user, db):
    s = UserSession(user_id=user.id, expires_at=now() + timedelta(minutes=config.ACCESS_TOKEN_MINUTES))
    db.add(s); db.commit()
    exp = s.expires_at
    return jwt.encode({"sub": user.id, "jti": s.id, "exp": exp.replace(tzinfo=__import__("datetime").timezone.utc)},
                      config.SECRET_KEY, algorithm="HS256")


_bearer = HTTPBearer(auto_error=False)


def current_session(creds=Depends(_bearer), db=Depends(get_db)):
    if not creds:
        raise HTTPException(401, "Not authenticated")
    try:
        p = jwt.decode(creds.credentials, config.SECRET_KEY, algorithms=["HS256"])
    except Exception:
        raise HTTPException(401, "Invalid or expired token")
    s = db.get(UserSession, p["jti"])
    u = db.get(User, p["sub"])
    if not s or s.revoked or s.expires_at < now() or not u or not u.is_active:
        raise HTTPException(401, "Session is no longer valid")
    return s, u


def current_user(su=Depends(current_session)):
    return su[1]


def require(perm):
    def dep(u=Depends(current_user)):
        if perm not in PERMS.get(u.role, []):
            raise HTTPException(403, "You do not have permission for this action")
        return u
    return dep


def case_filter(u):
    """SQL filter: admins see every case; others only cases they created or are assigned to."""
    if u.role == "admin":
        return true()
    sub = select(CaseAssignment.case_id).where(CaseAssignment.user_id == u.id)
    return or_(Case.created_by == u.id, Case.id.in_(sub))


def get_case(db, u, case_id):
    c = db.scalar(select(Case).where(Case.id == case_id, case_filter(u)))
    if not c:
        raise HTTPException(404, "Case not found")  # 404 (not 403) so existence is not leaked
    return c


def get_evidence(db, u, eid):
    e = db.scalar(select(Evidence).join(Case, Case.id == Evidence.case_id).where(Evidence.id == eid, case_filter(u)))
    if not e:
        raise HTTPException(404, "Evidence not found")
    return e


SENSITIVE = {"password", "token", "access_token", "secret", "new_password", "current_password"}


def _digest(prev, ev):
    s = "|".join(str(x) for x in (prev, ev.event_id, ev.ts.isoformat(), ev.actor_name, ev.action, ev.object_type,
                                  ev.object_id, ev.outcome, json.dumps(ev.meta, sort_keys=True)))
    return hashlib.sha256(s.encode()).hexdigest()


def audit(db, actor, action, otype=None, oid=None, outcome="success", **meta):
    clean = json.loads(json.dumps({k: v for k, v in meta.items() if k.lower() not in SENSITIVE}, default=str))
    last = db.scalar(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1))
    ev = AuditEvent(ts=now(), actor_id=actor.id if actor else None, actor_name=actor.username if actor else None,
                    action=action, object_type=otype, object_id=oid, outcome=outcome, meta=clean,
                    prev_hash=last.hash if last else "0" * 64)
    from .db import uid
    ev.event_id = uid()
    ev.hash = _digest(ev.prev_hash, ev)
    db.add(ev); db.commit()


def verify_audit_chain(db):
    prev, n = "0" * 64, 0
    for ev in db.scalars(select(AuditEvent).order_by(AuditEvent.seq)):
        if ev.prev_hash != prev or ev.hash != _digest(prev, ev):
            return {"valid": False, "broken_at_seq": ev.seq, "checked": n}
        prev, n = ev.hash, n + 1
    return {"valid": True, "checked": n}
