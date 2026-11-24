# DFIS — Complete Setup Guide for Teammate (Windows)

Follow these commands **in order, top to bottom**. Do not skip any step.

---

## STEP 0 — Check prerequisites (one time)

Open **PowerShell** and run:

```powershell
python --version
```

You must see **Python 3.10 or newer** (e.g. `Python 3.12.x`).
If you don't have Python: download it from https://www.python.org/downloads/
and during install **check the box "Add Python to PATH"**, then close and reopen PowerShell.

Check git too:

```powershell
git --version
```

If missing: https://git-scm.com/download/win

---

## STEP 1 — Get the project code (one time)

```powershell
cd $HOME\Desktop
git clone <YOUR_REPO_URL> dfis
cd dfis
```

Replace `<YOUR_REPO_URL>` with the real URL of the GitHub/GitLab repo
(or, if you received the project as a ZIP from OneDrive: extract it, then
`cd` into the extracted `dfis` folder instead).

---

## STEP 2 — One-command setup (one time)

This creates the virtual environment, installs every dependency, and creates `.env`
with **your own** random secret key and an initial admin password. The script prints
that admin login at the end; write it down.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
```

Manual equivalent (only if the script fails for some reason):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
Copy-Item .env.example .env   # then edit .env as described in STEP 3
```

---

## STEP 3 — Configure .env (one time)

```powershell
notepad .env
```

If you used `setup.ps1`, this is already done; skip to STEP 4.

Otherwise, replace the two `CHANGE_ME` values with your own, then save and close:

```dotenv
DFIS_SECRET_KEY=<paste the output of: python -c "import secrets; print(secrets.token_hex(32))">
DFIS_ADMIN_PASSWORD=<choose a strong password>
```

Every team member has **their own** secrets. Never share or commit `.env`.

> Note: `DFIS_DATABASE_URL` must be exactly
> `sqlite:///./backend/data/dfis.db` (three slashes, one dot before the slash).

---

## STEP 4 — (Optional) Get the shared data: cases + evidence

The database and uploaded evidence files are **not in git**.
If your teammate needs your existing cases/evidence, zip the folder
`backend\data\` on YOUR machine, share it (OneDrive/Drive/USB), and on HIS machine:

```powershell
# copy the received zip into the project root first, then:
Expand-Archive backend-data.zip -DestinationPath backend -Force
```

This recreates `backend\data\dfis.db` and `backend\data\storage\originals\...`.
If he starts clean instead, skip this step — the app creates an empty database on first run.

---

## STEP 5 — Verify installation (one time, recommended)

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Expected: all tests pass (no `FAILED` lines).

---

## STEP 6 — Start the server (EVERY time you work)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_server.ps1
```

Or manually:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload
```

Then open in the browser:

- App: **http://localhost:8000**
- API docs: **http://localhost:8000/docs**

Login: **admin** with the password printed by `setup.ps1` (or the one you put in `.env`).
Change it inside DFIS after your first login.

Stop the server: press **Ctrl+C** in the terminal.

---

## STEP 7 — Everyday routine (after setup is done)

```powershell
cd $HOME\Desktop\dfis
powershell -ExecutionPolicy Bypass -File scripts\start_server.ps1
```

Open http://localhost:8000 . That's all.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `python` not recognized | Reinstall Python with "Add to PATH" checked; reopen PowerShell |
| `scripts\setup.ps1` blocked | Run exactly with `powershell -ExecutionPolicy Bypass -File ...` |
| `pip install` fails / slow | Check internet; retry: `.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt` |
| Login fails | Check `.env` values from STEP 3 are saved; restart the server |
| Port 8000 already in use | Another server is running — close the old terminal, or change port: `.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload --port 8001` |
| "Must change password at first login" | That is normal — set a new password when prompted |

---

## Quick reference card (print this)

```
FIRST TIME ONLY:
  cd dfis
  powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
  notepad .env                 # paste shared credentials
  .\.venv\Scripts\python.exe -m pytest -q

EVERY DAY:
  powershell -ExecutionPolicy Bypass -File scripts\start_server.ps1
  open http://localhost:8000
```
