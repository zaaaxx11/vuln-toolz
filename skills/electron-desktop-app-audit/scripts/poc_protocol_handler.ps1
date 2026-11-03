# Benign protocol-handler PoC for shell.openExternal findings.
#
# Proves "an arbitrary scheme reaches the OS shell and executes a program"
# WITHOUT weaponising ms-msdt / ms-appinstaller / search-ms. Those real
# handlers install packages, spawn diagnostic tooling, or leak NTLM -- they
# can break the operator's box or trip AV, and the finding does not need them.
#
# This installs a throwaway handler under HKCU (NO admin required) that only
# appends one timestamped line to a log. If that line appears after the target
# app processes attacker-controlled input, arbitrary code execution is proven:
# Windows ran a program of the attacker's choosing.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File poc_protocol_handler.ps1
#   powershell -ExecutionPolicy Bypass -File poc_protocol_handler.ps1 -Scheme poc-x -Dir C:\poc
#   powershell -ExecutionPolicy Bypass -File poc_protocol_handler.ps1 -Uninstall
#
# ALWAYS run the self-test (step L0) before testing the target. A handler that
# does not fire on `start <scheme>:selftest` will not fire for the target
# either, and a silent no-op reads as "target is safe" -- a false negative.

param(
    [string]$Scheme = "poc-zoya",
    [string]$Dir    = "C:\poc",
    [string]$Tag    = "poc",
    [switch]$Uninstall
)

$base = "HKCU:\Software\Classes\$Scheme"
$log  = Join-Path $Dir "$Tag`_proof.log"
$cmd  = Join-Path $Dir "$Tag`_handler.cmd"

if ($Uninstall) {
    if (Test-Path $base) { Remove-Item -Recurse -Force $base }
    Write-Host "[+] handler '$Scheme:' removed. (log + folder left in place for evidence)"
    exit 0
}

New-Item -ItemType Directory -Force -Path $Dir | Out-Null

# Handler body: log the full URI, execute nothing from it.
$handler = @"
@echo off
echo [%DATE% %TIME%] FIRED $Tag "%~1" >> "$log"
exit /b 0
"@
Set-Content -Path $cmd -Value $handler -Encoding ASCII

New-Item -Path $base -Force | Out-Null
Set-ItemProperty -Path $base -Name "(Default)"    -Value "URL:$Tag protocol"
Set-ItemProperty -Path $base -Name "URL Protocol" -Value ""
New-Item -Path "$base\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "$base\shell\open\command" -Name "(Default)" -Value "`"$cmd`" `"%1`""

Write-Host "[+] installed. scheme = $Scheme`:"
Write-Host "    log = $log"
Write-Host ""
Write-Host "[i] STEP L0 -- SELF-TEST (must pass BEFORE touching the target):"
Write-Host "      start $Scheme`:selftest"
Write-Host "      Get-Content `"$log`"          # expect exactly 1 line containing 'selftest'"
Write-Host "      Remove-Item `"$log`"          # clear it so the real run is unambiguous"
Write-Host ""
Write-Host "[i] CONTROL: if the self-test writes nothing, the handler is not"
Write-Host "    registered correctly. STOP. Do not proceed and do not report"
Write-Host "    'no execution observed' -- that would be a false negative."
