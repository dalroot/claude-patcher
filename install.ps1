# ==============================================================================
# Claude Patcher (clp) Universal Global Installer for Windows
# ==============================================================================
$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Claude Desktop Privacy & Security Shield (clp)       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Verify Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "[-] Python 3.9+ is required but not found in PATH.`nPlease install Python from https://python.org or the Microsoft Store."
    exit 1
}

$pyVersion = python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'
Write-Host "[+] Detected Python version: $pyVersion" -ForegroundColor Green

# 2. Install dependency: rich
Write-Host "[+] Ensuring dependencies (rich>=13.0.0)..." -ForegroundColor Green
python -m pip install --quiet rich>=13.0.0

# 3. Create global installation directory
$installDir = "$env:LOCALAPPDATA\Programs\claude-patcher"
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# 4. Source file resolution (local file or download from GitHub)
$targetScript = "$installDir\claude_patcher.py"
$localScript = Join-Path $PSScriptRoot "claude_patcher.py"

if (Test-Path $localScript) {
    Copy-Item -Path $localScript -Destination $targetScript -Force
} else {
    Write-Host "[+] Downloading latest claude_patcher.py from GitHub..." -ForegroundColor Green
    $url = "https://raw.githubusercontent.com/dalroot/claude-patcher/main/claude_patcher.py"
    Invoke-WebRequest -Uri $url -OutFile $targetScript -UseBasicParsing
}

# 5. Generate global batch wrappers for CMD & PowerShell
$batchContent = "@echo off`r`npython `"$targetScript`" %*"
Set-Content -Path "$installDir\clp.cmd" -Value $batchContent -Force
Set-Content -Path "$installDir\claude-patcher.cmd" -Value $batchContent -Force

# 6. Ensure install directory is in User PATH
$userPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::User)
if ($userPath -split ';' -notcontains $installDir) {
    Write-Host "[+] Adding $installDir to User PATH..." -ForegroundColor Green
    $newPath = "$userPath;$installDir".Trim(';')
    [Environment]::SetEnvironmentVariable("PATH", $newPath, [EnvironmentVariableTarget]::User)
    $env:PATH = "$env:PATH;$installDir"
}

# Also link into WindowsApps if available for instant execution without restart
$winApps = "$env:LOCALAPPDATA\Microsoft\WindowsApps"
if (Test-Path $winApps) {
    Copy-Item -Path "$installDir\clp.cmd" -Destination "$winApps\clp.cmd" -Force -ErrorAction SilentlyContinue
    Copy-Item -Path "$installDir\claude-patcher.cmd" -Destination "$winApps\claude-patcher.cmd" -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [OK] Claude Patcher (clp) installed globally!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " You can now run 'clp' from ANY terminal window:" -ForegroundColor Yellow
Write-Host "   - clp          : Open Interactive Security Center" -ForegroundColor Yellow
Write-Host "   - clp doctor   : Run Evidence-Based Security Audit" -ForegroundColor Yellow
Write-Host "   - clp apply    : Deploy Enterprise MDM & Anti-Leak Shield" -ForegroundColor Yellow
Write-Host "   - clp rollback : 100% Atomic Rollback to Factory State" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
