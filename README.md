# DFIS - Digital Forensics Investigation System (academic prototype)

Working web app: FastAPI backend + SQLAlchemy (SQLite by default, PostgreSQL supported) + a dependency-free
frontend (HTML/CSS/vanilla JS, served by the backend). **Not forensically certified, legally validated or court-ready.**

## Quick start (no Docker)
```bash
cd dfis
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt
cp .env.example .env                                   # optional; edit values
uvicorn backend.app.main:app --reload
```
Open http://localhost:8000 . On first start the console prints the initial admin login
(username `admin`, random password, shown once) unless `DFIS_ADMIN_PASSWORD` is set. You must change it at first login.
API docs (OpenAPI): http://localhost:8000/docs

## Docker + PostgreSQL
```bash
cp .env.example .env     # set DFIS_SECRET_KEY, POSTGRES_PASSWORD
docker compose up --build
```

## Tests
```bash
pytest -q
```
Covers: auth/lockout, RBAC, case isolation, upload validation (type, size, traversal filename), SHA-256 + tamper detection,
append-only custody/audit, log parsing, timestamp normalization, timeline, PDF report, audit-chain verification.
(Synthetic data only. Frontend has no automated tests.)

## Modules (all implemented against the real DB)
Auth/users/RBAC (admin, lead, analyst, custodian, reviewer) - cases - evidence (streamed ingestion, SHA-256, read-only
reference copy, working-copy analysis) - integrity verification (MATCH / MISMATCH / ERROR) - file & metadata analysis
(signatures, Pillow EXIF, PDF, DOCX/ZIP listing, never executed) - log analysis (JSONL + text, configurable rules) -
timeline (UTC normalization, assumptions shown, undated events listed) - chain of custody (append-only, acknowledgments) -
PDF reports (ReportLab) - hash-chained audit trail - dashboard - settings.

## Security notes
Argon2id passwords, 5-failure lockout, revocable short-lived JWT sessions (`/auth/refresh`), permissions enforced on the
backend, cross-case access returns 404, filename sanitising + extension allow-list + size limit, originals chmod 0444,
CSV-injection protection, CSP/nosniff headers, no stack traces or file paths in responses, secrets only via environment.
Use HTTPS (reverse proxy) in production.

## Known limitations / deviations (honest list)
- Frontend is vanilla JS + hand-written CSS instead of React/Tailwind/shadcn/Recharts (zero build step; charts are CSS bars).
- Tables are created with `create_all`; Alembic migrations are not included yet.
- Analysis jobs run synchronously inside the request (status recorded); no background queue/cancellation.
- Account recovery = administrator password reset (no email flow). Rate limiting is per-account lockout only.
- Audit chain detects tampering via `/audit/verify` but a DB admin could rewrite the whole chain; production needs external
  write-once storage. Storage is local disk (no encryption at rest); object-storage abstraction not implemented.
- Not yet implemented: secure-deletion/retention enforcement jobs (retention date is recorded on archive), ERD diagram.
- Tests were written but must be run on your machine (`pytest`); they were not executed in the authoring sandbox.
