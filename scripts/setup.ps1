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

# 2. .env from the committed template (only if missing)
if (-not (Test-Path .env)) {
    Copy-Item .env.example .env
    Write-Host "Created .env from .env.example" -ForegroundColor Green
} else {
    Write-Host ".env already exists, leaving it alone" -ForegroundColor Yellow
}

Write-Host "`nSetup complete. Start the server with:" -ForegroundColor Cyan
Write-Host "  powershell -ExecutionPolicy Bypass -File scripts\start_server.ps1"
