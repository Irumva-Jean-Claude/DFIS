"""DFIS application entry point."""
import secrets
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, text
from . import config
from .db import Base, engine, SessionLocal, User, _ensure_triggers_after_create
from .security import hash_pw, audit
from .api_core import auth_r, users_r, cases_r, dash_r, audit_r, settings_r, health_r
from .api_evidence import evidence_r, integrity_r, custody_r
from .api_analysis import file_r, log_r, timeline_r
from .api_reports import reports_r

app = FastAPI(
    title=config.ORG_NAME,
    version=config.SYSTEM_VERSION,
    description="Digital Forensics Investigation System — secure evidence management and case tracking.",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)
for r in (health_r, auth_r, users_r, cases_r, dash_r, audit_r, settings_r,
          evidence_r, integrity_r, custody_r, file_r, log_r, timeline_r, reports_r):
    app.include_router(r, prefix="/api/v1")


@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)
    _ensure_triggers_after_create(engine)
    with engine.connect() as conn:
        if engine.dialect.name == "sqlite":
            cols = [r[1] for r in conn.exec_driver_sql("PRAGMA table_info(users)")]
            migrations = {
                "totp_secret":        "ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64)",
                "mfa_enabled":        "ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT 0",
                "account_status":     "ALTER TABLE users ADD COLUMN account_status VARCHAR(20) DEFAULT 'active'",
            }
            for col, sql in migrations.items():
                if col not in cols:
                    conn.exec_driver_sql(sql)
                    conn.commit()
    with SessionLocal() as db:
        if not db.scalar(select(User).limit(1)):
            pw = config.ADMIN_PASSWORD or secrets.token_urlsafe(12) + "9a"
            a = User(username=config.ADMIN_USERNAME.lower(), full_name="System Administrator",
                     role="admin", password_hash=hash_pw(pw), must_change_password=not bool(config.ADMIN_PASSWORD))
            db.add(a); db.commit()
            audit(db, a, "system_initialized", "user", a.id, version=config.SYSTEM_VERSION)
            if not config.ADMIN_PASSWORD:
                print(f"\n*** Initial admin: username='{a.username}' password='{pw}' (change at first login) ***\n")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if not request.url.path.startswith(("/api/docs", "/api/redoc", "/api/openapi")):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; frame-ancestors 'none'"
        )
    return resp


@app.exception_handler(PermissionError)
async def perm_handler(request, exc):
    return JSONResponse({"detail": str(exc)}, status_code=409)


@app.exception_handler(Exception)
async def generic_handler(request, exc):
    return JSONResponse({"detail": "An unexpected error occurred. Contact your system administrator."}, status_code=500)


FRONT = Path(__file__).resolve().parents[2] / "frontend-dist"
if not FRONT.exists():
    FRONT = Path(__file__).resolve().parents[2] / "frontend"
if FRONT.exists():
    app.mount("/", StaticFiles(directory=FRONT, html=True), name="frontend")
