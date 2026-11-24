# ==============================================================================
# Claude Patcher (clp) Universal Global Installer for Windows
# Modular Enterprise Edition
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

# 2. Install package via pip (Modular Package Architecture)
if (Test-Path (Join-Path $PSScriptRoot "pyproject.toml")) {
    Write-Host "[+] Installing local modular package from $PSScriptRoot..." -ForegroundColor Green
    python -m pip install --quiet --upgrade $PSScriptRoot
} else {
    Write-Host "[+] Installing latest modular package from GitHub repository..." -ForegroundColor Green
    python -m pip install --quiet --upgrade "git+https://github.com/dalroot/claude-patcher.git"
}

# 3. Create global installation directory
$installDir = "$env:LOCALAPPDATA\Programs\claude-patcher"
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# 4. Generate global batch wrappers for CMD & PowerShell
$batchContent = "@echo off`r`npython -m claude_patcher %*"
Set-Content -Path "$installDir\clp.cmd" -Value $batchContent -Force
Set-Content -Path "$installDir\claude-patcher.cmd" -Value $batchContent -Force

# 5. Ensure install directory is in User PATH
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
Write-Host "==========================================================" -ForegroundColor Green
Write-Host " [✓] Claude Patcher (clp) installed globally on Windows!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host " You can now run 'clp' from ANY CMD or PowerShell terminal:" -ForegroundColor Yellow
Write-Host "   - clp          : Open Interactive Security Center"
Write-Host "   - clp doctor   : Run Evidence-Based Security Audit"
Write-Host "   - clp apply    : Deploy Enterprise MDM & Anti-Leak Shield"
Write-Host "   - clp rollback : 100% Atomic Rollback to Factory State"
Write-Host "==========================================================" -ForegroundColor Green
