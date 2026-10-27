<#
.SYNOPSIS
  Build the standalone Windows edition (PortableSecurityAudit.exe) with PyInstaller.

.DESCRIPTION
  Run on a Windows 10/11 build workstation with Python 3.12 installed (py launcher).
  The result runs on target PCs without Python. It does NOT run on Linux.

    powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
    powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1 -OneFile
    powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1 -SignThumbprint <certificate thumbprint>

.PARAMETER OneFile
  Build a single .exe instead of the default folder (exe + _internal\). A single
  file unpacks itself into %TEMP% on every run and is flagged more often by antivirus.

.PARAMETER SignThumbprint
  SHA-1 thumbprint of a code-signing certificate in the current user's store. When
  given, the executable is Authenticode-signed with signtool (Windows SDK).

.PARAMETER PythonExe
  Full path of the Python interpreter to build with (default: the py launcher with -PythonVersion).

.PARAMETER TimestampUrl
  RFC 3161 timestamp server used when signing.
#>
param(
    [switch]$OneFile,
    [switch]$SkipTests,
    [string]$SignThumbprint = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$PythonVersion = "3.12",
    [string]$PythonExe = ""
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

# Use an explicit interpreter if given (CI), otherwise the py launcher.
if ($PythonExe) { & $PythonExe -m venv .build-venv } else { & py "-$PythonVersion" -m venv .build-venv }
if ($LASTEXITCODE -ne 0) { throw "could not create the build virtual environment" }
$Python = Join-Path $Root ".build-venv\Scripts\python.exe"
# Hash-locked: every package (and its dependencies) must match requirements-build.lock.
& $Python -m pip install --require-hashes --only-binary=:all: -r requirements-build.lock
if ($LASTEXITCODE -ne 0) { throw "dependency installation failed" }

if (-not $SkipTests) {
    $env:PYTHONPATH = Join-Path $Root "src"
    & $Python -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "tests failed" }
}

& $Python packaging\make_version_info.py
Remove-Item -Recurse -Force build\windows, dist\windows -ErrorAction SilentlyContinue
$env:PSA_ONEFILE = if ($OneFile) { "1" } else { "0" }
& $Python -m PyInstaller --noconfirm --clean --distpath dist\windows --workpath build\windows packaging\psa.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

$Exe = if ($OneFile) { "dist\windows\PortableSecurityAudit.exe" } else { "dist\windows\PortableSecurityAudit\PortableSecurityAudit.exe" }

if ($SignThumbprint) {
    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $signtool) { throw "signtool.exe not found (install the Windows SDK)" }
    & $signtool.Source sign /sha1 $SignThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $Exe
    if ($LASTEXITCODE -ne 0) { throw "signing failed" }
    & $signtool.Source verify /pa $Exe
}

# Smoke test: version and a demo assessment (demo mode runs no commands).
& $Exe --version
if ($LASTEXITCODE -ne 0) { throw "smoke test (--version) failed" }
$Smoke = Join-Path ([System.IO.Path]::GetTempPath()) ("psa-smoke-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Smoke | Out-Null
& $Exe audit --demo --operator "Build smoke test" --reference "BUILD" --confirm "I AM AUTHORIZED" --output $Smoke | Out-Null
if ($LASTEXITCODE -ne 0) { throw "smoke test (demo audit) failed" }
$Report = Get-ChildItem -Directory $Smoke | Select-Object -First 1
& $Exe verify-report $Report.FullName | Out-Null
if ($LASTEXITCODE -ne 0) { throw "smoke test (verify-report) failed" }
Remove-Item -Recurse -Force $Smoke

Write-Host "Built: $Exe"
Get-FileHash -Algorithm SHA256 $Exe | Format-List
Write-Host "Next: py scripts\prepare_usb.py E:\PortableSecurityAudit --windows-build dist\windows\PortableSecurityAudit"
