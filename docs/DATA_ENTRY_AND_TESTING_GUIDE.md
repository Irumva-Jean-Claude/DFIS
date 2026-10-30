# DFIS — Data Entry & System Accuracy Testing Guide

This guide explains **how to enter data** into DFIS, gives you **ready-made test data**
(in `test-data/`), and shows **how to verify the system is working accurately**.

> Remember: DFIS is an academic prototype. Tests here check *correctness of the
> software's logic*, not forensic certification.

---

## 1. Starting the system

```powershell
cd c:\Users\JClaude\OneDrive\Desktop\dfis\dfis
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --port 8000
```

- Web UI:  http://localhost:8000
- API docs: http://localhost:8000/docs  (interactive OpenAPI — you can call every endpoint from there)

Log in with the admin account from `.env` (default in your `.env`):
`irumva / irumvajc123`. You will be forced to change it at first login if it's a fresh DB.

### Roles and what they may do (RBAC)

| Role       | Can do |
|------------|--------|
| admin      | everything, incl. users, settings, audit verify |
| lead       | everything except user/settings management |
| analyst    | read cases, run analyses, write timeline |
| custodian  | evidence custody handling |
| reviewer   | read-only |

For full testing, create at least one user per role (see §2).

---

## 2. Data entry — the correct order

DFIS is workflow-ordered. You **must** enter data in this sequence:

```
users  →  case  →  assign investigators  →  evidence upload  →  integrity verify
→  analyses (file / log)  →  custody transfers  →  timeline events  →  PDF report
```

### Step 1 — Create users (admin only)

UI: **Users** page → *New user*. Fill username, full name, role, initial password
(temporary — the user must change it at next login).

| Field      | Rule |
|------------|------|
| username   | 3–40 chars, letters/digits/`_.-` only, lowercased |
| role       | admin, lead, analyst, custodian, reviewer |
| password   | must pass the password policy |

### Step 2 — Create a case

UI: **Cases** → *New case*.

| Field      | Rule |
|------------|------|
| title      | 3–200 chars (required) |
| category   | free text, default `general` |
| priority   | `low` \| `medium` \| `high` \| `critical` |
| description| up to 5000 chars |

The system auto-generates the case reference `DFIS-<year>-NNNN`.
The creator is automatically assigned to the case.

### Step 3 — Assign investigators

UI: case detail → **Assign**. Users must exist and be active. Only assigned
users (or admins) can see the case afterwards — cross-case access returns 404
(this is one of the things you should test, §4).

### Step 4 — Upload evidence

UI: case detail → *Add evidence*. The upload form requires:

| Field              | Rule |
|--------------------|------|
| evidence_type      | one of `document`, `image`, `archive`, `system_log`, `text`, `other` |
| source             | ≤ 200 chars, e.g. "Workstation WS-01 C: drive" |
| acquisition_method | ≤ 200 chars, e.g. "logical copy via FTK Imager" |
| acquisition_date   | optional; ISO-8601 recommended: `2026-10-25T14:30:00Z` (other formats are normalized to UTC with a note) |
| submitted_by       | ≤ 100 chars |
| received_by        | ≤ 100 chars |
| file               | see allowed types below |

**Allowed file extensions:** `.pdf .txt .log .json .jsonl .csv .png .jpg .jpeg
.gif .bmp .zip .docx .xlsx .xml .eml .md`

**Hard limits enforced by the system (good things to try to break):**

- max upload size = 50 MB (`DFIS_MAX_UPLOAD_MB`)
- empty files rejected
- filenames sanitized (`../../evil.pdf` → `.._.._evil.pdf`); control chars and
  special chars replaced with `_`
- file is hashed (SHA-256) at ingestion and stored **read-only** as the
  reference copy
- evidence cannot be added to a closed/archived case (HTTP 409)

### Step 5 — Verify integrity

UI: evidence detail → **Verify integrity**. The system recalculates the SHA-256
of the stored original and compares it with the value recorded at ingestion:

- `MATCH` — the stored file still equals what was ingested
- `MISMATCH` — the stored file differs from ingestion (tamper detection)
- `ERROR` — file missing/unreadable

### Step 6 — Run analyses

Two analysis types, both run on a temporary **working copy** (the original is
never touched):

- **File analysis** — signature/magic-byte check vs extension, EXIF for images
  (Pillow), PDF metadata, DOCX/XLSX (ZIP) member listing, text preview. Also
  feeds detected timestamps into the timeline.
- **Log analysis** — parses **JSON Lines** (keys: `timestamp|time|ts`, `message`,
  `event_type`, `source|host`, `user`) or **timestamped text logs** (syslog-like
  `2026-10-25 14:30:00 host proc[123]: message`). Produces:
  - normalized events (UTC) — viewable, filterable, CSV-exportable
  - alerts: repeated authentication failures (≥ threshold within a time window),
    privilege-related events (keywords `sudo`, `su:`, `privilege`, `escalat`,
    `added to group`, `setuid`), and your custom keywords (Settings page)
  - grouping by event type/source

### Step 7 — Chain of custody

- **Transfer**: current custodian (or lead/admin) transfers evidence to another
  user **assigned to the same case**. Status becomes `transfer_pending`.
- **Acknowledge**: only the recipient can acknowledge; custody then moves.
  Only one pending transfer at a time (409 otherwise).
- **Correction note**: admin-only; appends a note, history is never edited.

### Step 8 — Timeline

- Automatic events: acquisition, custody, log events, file-metadata timestamps.
- Manual events (analyst): title, details, `original_ts`, optional
  `tz_offset_minutes` applied when the parser had to *assume* UTC.
- Filter by category/evidence/time range; undated events are listed separately.

### Step 9 — Reports & audit

- **Reports**: generate a PDF case report (ReportLab) and download it.
- **Audit trail**: every action is recorded in a hash-chained log. Admin can
  run **Audit → Verify** — it must report the chain is intact.

---

## 3. Ready-made test data (in `test-data/`)

| File | Purpose |
|------|---------|
| `auth_failures.log` | 6 failed logins + 1 success for user `jsmith` in 4 minutes → **must trigger** the `repeated_authentication_failures` alert (threshold 5 / 10 min) |
| `sudo_suspicious.log` | normal events + `sudo`/`added to group` lines → **must trigger** `privilege_related_event` alerts |
| `events.jsonl` | JSON Lines log with mixed events, ISO timestamps with offsets → tests JSON parsing + UTC normalization (a `+03:00` event must shift to UTC) |
| `malformed.log` | lines without recognizable timestamps and a broken JSON line → tests the error-reporting path (parsed + malformed counts) |
| `evidence_notes.txt` | plain text for basic file analysis + metadata timeline |
| `make_test_image.py` | generates `photo_with_exif.jpg` containing EXIF GPS/Make/Model timestamps — run it first, then upload the JPG to test EXIF extraction |

Generate the test image once:

```powershell
.\.venv\Scripts\python.exe test-data\make_test_image.py
```

---

## 4. How to verify the system is accurate (test plan)

Run the automated end-to-end script first, then spot-check the expected values.

### 4.1 Automated end-to-end check

```powershell
# server must be running on :8000
.\.venv\Scripts\python.exe scripts\seed_and_test.py
```

The script logs in as admin, creates a fresh case and one user of each role,
uploads the sample evidence files, and asserts **37 checks** including:

- case ref auto-generation, status-flow rules (illegal transitions rejected)
- RBAC (analyst cannot create cases/users; custodian cannot read other cases)
- SHA-256 recorded at ingestion equals the real SHA-256 of the file on disk
- cross-case access returns 404; bad extension rejected (415); empty file rejected
- integrity verify returns `MATCH`
- log analysis alerts fire exactly as expected (`auth_failures.log` → 1 auth-failure
  alert with count 6; `sudo_suspicious.log` → privilege alert; `events.jsonl` →
  correct UTC normalization of the `+03:00` timestamp)
- custody transfer → acknowledge round-trip changes the custodian
- timeline includes acquisition + analyst events; PDF report downloads (non-empty);
  audit chain verifies OK

Each check prints `PASS`/`FAIL` and the script exits non-zero on any failure —
that is your quick regression check after any code change.

### 4.2 Manual spot-checks (the "is it accurate?" checklist)

1. **Hash accuracy** — compute the hash yourself and compare:
   ```powershell
   Get-FileHash test-data\auth_failures.log -Algorithm SHA256
   ```
   The value shown in DFIS evidence detail must match exactly.

2. **Tamper detection** — verify integrity (expect MATCH). Then, as an
   administrator, modify the stored original under `backend\data\storage\originals\`
   (take ownership / remove read-only), change one byte, and verify again →
   you must get `MISMATCH`.

3. **UTC normalization** — in `events.jsonl` the event
   `2026-10-25T09:00:00+03:00` must appear in the log-event list as
   `2026-10-25T06:00:00Z`, with the original value preserved in `ts_original`.

4. **Alert threshold boundary** — `auth_failures.log` has 6 failures for `jsmith`
   within 4 minutes. Set the threshold to 7 in Settings → re-run log analysis →
   the auth-failure alert must **disappear**. Set back to 5 → it must return.

5. **RBAC / case isolation** — log in as an analyst not assigned to the case:
   the case must not be visible (404), and the Users/Settings pages must be
   denied.

6. **Audit chain** — perform a few actions, then Audit → Verify: chain OK.
   (Directly editing the `audit_events` table in the SQLite DB is a known
   limitation the README admits — a full DB rewrite is not detected; that is
   documented, not a bug to test.)

7. **Status flow** — try to PATCH a case from `archived` to `open` → must be
   rejected (409). Allowed moves only: open→active/closed, active→closed,
   closed→active/archived.

### 4.3 The full pytest suite

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Covers auth/lockout, RBAC, case isolation, upload validation, hashing/tamper,
append-only custody, log parsing, timestamps, timeline, PDF, audit chain.

---

## 5. Quick workflow recap (cheat sheet)

```
1. Log in (admin)
2. Users → create analyst2 / custodian2 (temporary passwords)
3. Cases → new case "Test intrusion case", priority high
4. Assign analyst2, custodian2 to the case
5. Evidence → upload test-data\auth_failures.log as system_log
   source "WS-01 /var/log/auth.log", method "logical copy",
   date 2026-10-25T14:30:00Z
6. Verify integrity → MATCH
7. Log analysis → expect 1 auth-failure alert (jsmith, 6 failures)
8. Custody → transfer to custodian2; log in as custodian2 → acknowledge
9. Timeline → add analyst event "Incident detected"
10. Reports → generate PDF
11. Audit → verify chain OK
12. Run scripts\seed_and_test.py for the automated 37-check pass
```
