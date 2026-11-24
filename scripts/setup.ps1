# One-command project setup for teammates.
# Run in PowerShell from the project root:
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

# 1. Python virtual environment
if (-not (Test-Path .venv)) {
    python -m venv .venv
    Write-Host "Created .venv" -ForegroundColor Green
}
& .\.venv\Scripts\python.exe -m pip install --upgrade pip --quiet
& .\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt

# 2. .env from the committed template (only if missing), with this machine's own secrets
if (-not (Test-Path .env)) {
    $secret = & .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
    $adminPw = & .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(12) + '9a')"
    (Get-Content .env.example) `
        -replace '^DFIS_SECRET_KEY=.*', "DFIS_SECRET_KEY=$secret" `
        -replace '^DFIS_ADMIN_PASSWORD=.*', "DFIS_ADMIN_PASSWORD=$adminPw" |
        Set-Content -Encoding utf8 .env
    Write-Host "Created .env with a new random secret key" -ForegroundColor Green
    Write-Host "Initial admin login -> username: admin  password: $adminPw" -ForegroundColor Cyan
    Write-Host "(Change this password inside DFIS after your first login.)" -ForegroundColor Cyan
} else {
    Write-Host ".env already exists, leaving it alone" -ForegroundColor Yellow
}

Write-Host "`nSetup complete. Start the server with:" -ForegroundColor Cyan
Write-Host "  powershell -ExecutionPolicy Bypass -File scripts\start_server.ps1"
