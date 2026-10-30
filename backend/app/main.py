"""DFIS application entry point."""
import secrets
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from . import config
from .db import Base, engine, SessionLocal, User
from .security import hash_pw, audit
from .api_core import auth_r, users_r, cases_r, dash_r, audit_r, settings_r
from .api_evidence import evidence_r, integrity_r, custody_r
from .api_analysis import file_r, log_r, timeline_r
from .api_reports import reports_r

app = FastAPI(title="Digital Forensics Investigation System (DFIS)", version="1.0.0",
              description="Academic prototype. Not forensically certified or court-ready.")
for r in (auth_r, users_r, cases_r, dash_r, audit_r, settings_r, evidence_r, integrity_r, custody_r, file_r, log_r, timeline_r, reports_r):
    app.include_router(r, prefix="/api/v1")


@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)
    # lightweight migration for databases created before MFA support
    with engine.connect() as conn:
        cols = [r[1] for r in conn.exec_driver_sql("PRAGMA table_info(users)")] if engine.dialect.name == "sqlite" else None
        if cols is not None:
            if "totp_secret" not in cols:
                conn.exec_driver_sql("ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64)"); conn.commit()
            if "mfa_enabled" not in cols:
                conn.exec_driver_sql("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN"); conn.commit()
    with SessionLocal() as db:
        if not db.scalar(select(User).limit(1)):
            pw = config.ADMIN_PASSWORD or secrets.token_urlsafe(12) + "9a"
            a = User(username=config.ADMIN_USERNAME.lower(), full_name="System Administrator", role="admin",
                     password_hash=hash_pw(pw), must_change_password=True)
            db.add(a); db.commit()
            audit(db, a, "initial_admin_created", "user", a.id)
            if not config.ADMIN_PASSWORD:
                print(f"\n*** Initial admin: username='{a.username}' password='{pw}' (shown once; change it after login) ***\n")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if not request.url.path.startswith(("/docs", "/redoc", "/openapi")):
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; frame-ancestors 'none'"
    if request.url.path.startswith(("/js/", "/css/", "/index.html", "/")):
        resp.headers["Cache-Control"] = "no-cache"  # frontend updates apply on plain reload
    return resp


@app.exception_handler(PermissionError)
async def perm_handler(request, exc):
    return JSONResponse({"detail": str(exc)}, status_code=409)


@app.exception_handler(Exception)
async def generic_handler(request, exc):
    return JSONResponse({"detail": "Internal server error"}, status_code=500)  # no stack traces/paths leaked


FRONT = Path(__file__).resolve().parents[2] / "frontend"
if FRONT.exists():
    app.mount("/", StaticFiles(directory=FRONT, html=True), name="frontend")
