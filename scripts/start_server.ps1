# DFIS dev server launcher.
# Run:  powershell -ExecutionPolicy Bypass -File scripts\start_server.ps1
# Stop: press Ctrl+C in this terminal (server stops on your time, no timeout).

Set-Location (Split-Path $PSScriptRoot -Parent)
Write-Host "Starting DFIS server on http://127.0.0.1:8000 (Ctrl+C to stop)..." -ForegroundColor Cyan
& .\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload --port 8000
