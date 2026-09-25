# Optional Authenticode signing in CI (Windows runner).
#
#   powershell -File tools\sign_windows.ps1 dist\clipcloak\clipcloak.exe dist\x.msi
#
# Signs only if the CI/CD variable SIGN_PFX_BASE64 (code signing certificate as
# base64-encoded .pfx) is set; password in SIGN_PFX_PASSWORD, optional
# SIGN_TIMESTAMP_URL (default http://timestamp.digicert.com). Without the variable
# nothing happens. Needs signtool.exe from the Windows SDK.
# Signed binaries are far less likely to be blocked by SmartScreen or flagged by
# endpoint protection (ESET etc.).
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Files)

$ErrorActionPreference = "Stop"
if (-not $env:SIGN_PFX_BASE64) {
    Write-Host "SIGN_PFX_BASE64 not set - files are not signed"
    exit 0
}
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "signtool.exe not found - install the Windows SDK on the runner" }
$ts = if ($env:SIGN_TIMESTAMP_URL) { $env:SIGN_TIMESTAMP_URL } else { "http://timestamp.digicert.com" }
$pfx = Join-Path $env:TEMP ("codesign-" + [guid]::NewGuid().ToString() + ".pfx")
[IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:SIGN_PFX_BASE64))
try {
    & $signtool.FullName sign /fd SHA256 /f $pfx /p $env:SIGN_PFX_PASSWORD /tr $ts /td SHA256 $Files
    if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)" }
} finally {
    Remove-Item $pfx -Force -ErrorAction SilentlyContinue
}
