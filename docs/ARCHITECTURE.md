# Architecture
Browser SPA (frontend/) -> REST /api/v1 (FastAPI routers) -> security layer (JWT session check, RBAC, case filter, audit)
-> SQLAlchemy models -> DB; evidence files on disk (backend/data/storage/{originals,working,reports}).

Files: config.py (env), db.py (models), security.py (auth/RBAC/audit), forensic.py (hashing/analysis/log parsing),
api_core.py (auth, users, cases, dashboard, audit, settings), api_evidence.py (evidence, custody, integrity),
api_analysis.py (file/log analysis, timeline), api_reports.py (PDF).

## Entities
users, sessions, cases, case_assignments, evidence, custody_events (append-only), integrity_checks (append-only),
analysis_results, log_events, timeline_events, reports, audit_events (append-only, hash-chained), system_config.
Relations: case 1-N evidence 1-N {custody_events, integrity_checks, analysis_results, log_events}; case N-M users.

## Evidence lifecycle
Upload -> sanitise name + extension allow-list -> stream to tmp while enforcing size limit -> SHA-256 -> move to originals/<uuid>
(chmod 0444) -> evidence row + INGESTED custody event + audit. Analysis copies original to working/, analyses, deletes copy.
Verify = recompute SHA-256 of the original, compare with stored reference, append integrity_checks row + audit.

## Custody
INGESTED -> TRANSFER (custodian/lead/admin) -> ACKNOWLEDGED (recipient only). Corrections are new CORRECTION_NOTE events (admin).
ORM listeners block UPDATE/DELETE on custody, integrity and audit tables.

## Audit chain
hash_n = SHA256(hash_{n-1} | event fields). `/audit/verify` recomputes the chain.
