"""Configuration: environment variables (optionally from a .env file). No secrets in source."""
import os, secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = BASE_DIR.parent


def _load_env():
    for p in (BASE_DIR / ".env", ROOT_DIR / ".env"):
        if p.exists():
            for line in p.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip("\"'"))


_load_env()
E = os.environ.get
DATA_DIR = Path(E("DFIS_DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_URL = E("DFIS_DATABASE_URL", f"sqlite:///{DATA_DIR / 'dfis.db'}")

_kf = DATA_DIR / ".secret_key"
SECRET_KEY = E("DFIS_SECRET_KEY")
if not SECRET_KEY:  # dev fallback: generated once and persisted locally
    if not _kf.exists():
        _kf.write_text(secrets.token_hex(32))
        _kf.chmod(0o600)
    SECRET_KEY = _kf.read_text().strip()

ORIGINALS = DATA_DIR / "storage" / "originals"
WORKING = DATA_DIR / "storage" / "working"
REPORTS = DATA_DIR / "storage" / "reports"
TMP = DATA_DIR / "storage" / "tmp"
for d in (ORIGINALS, WORKING, REPORTS, TMP):
    d.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD_BYTES = int(float(E("DFIS_MAX_UPLOAD_MB", "50")) * 1024 * 1024)
ACCESS_TOKEN_MINUTES = int(E("DFIS_ACCESS_TOKEN_MINUTES", "30"))
LOCK_THRESHOLD, LOCK_MINUTES = 5, 15
RETENTION_DAYS = int(E("DFIS_RETENTION_DAYS", "2555"))
ADMIN_USERNAME = E("DFIS_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = E("DFIS_ADMIN_PASSWORD")  # if unset, a random one is printed once on first start
ALLOWED_EXT = {".pdf", ".txt", ".log", ".json", ".jsonl", ".csv", ".png", ".jpg", ".jpeg", ".gif", ".bmp",
               ".zip", ".docx", ".xlsx", ".xml", ".eml", ".md"}
EVIDENCE_TYPES = ["document", "image", "archive", "system_log", "text", "other"]
ORG_NAME = E("DFIS_ORG_NAME", "Digital Forensics Investigation System")
SYSTEM_VERSION = E("DFIS_VERSION", "1.0.0")
SESSION_IDLE_MINUTES = int(E("DFIS_SESSION_IDLE_MINUTES", "30"))
REQUIRE_USER_APPROVAL = E("DFIS_REQUIRE_USER_APPROVAL", "false").lower() == "true"
# Email (SMTP)
SMTP_HOST = E("DFIS_SMTP_HOST", "")
SMTP_PORT = int(E("DFIS_SMTP_PORT", "587"))
SMTP_USER = E("DFIS_SMTP_USER", "")
SMTP_PASS = E("DFIS_SMTP_PASS", "")
SMTP_FROM = E("DFIS_SMTP_FROM", "noreply@dfis.local")
SMTP_TLS  = E("DFIS_SMTP_TLS", "true").lower() == "true"
VIRUSTOTAL_KEY = E("DFIS_VIRUSTOTAL_KEY", "")
