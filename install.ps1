# Claude Patcher (clp) Quick Installer for Windows PowerShell
Write-Host "=== Claude Patcher (clp) Windows Installer ===" -ForegroundColor Cyan

# Check Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python is not found in PATH. Please install Python 3.9+ from https://python.org or the Microsoft Store."
    exit 1
}

Write-Host "[+] Installing dependencies..." -ForegroundColor Green
python -m pip install --quiet rich>=13.0.0

# Install as Python package locally
Write-Host "[+] Installing claude-patcher CLI..." -ForegroundColor Green
python -m pip install -e .

Write-Host ""
Write-Host "[OK] Installation complete!" -ForegroundColor Green
Write-Host "Run 'clp' or 'clp doctor' from any terminal." -ForegroundColor Yellow
