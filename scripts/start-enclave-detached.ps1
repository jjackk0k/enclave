# start-enclave-detached.ps1 — launches the Enclave console via WMI (winmgmt), fully
# detached from any console/Job so it survives the caller's exit. Idempotent: refuses
# to double-start when 8977 is already held.
$listener = Get-NetTCPConnection -LocalPort 8977 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($listener) { Write-Host "ALREADY-UP pid=$($listener.OwningProcess)"; exit 0 }
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
  CommandLine = '"C:\Program Files\nodejs\node.exe" "C:\Users\Jack\Downloads\enclave\server.mjs"'
  CurrentDirectory = 'C:\Users\Jack\Downloads\enclave'
}
if ($r.ReturnValue -ne 0) { Write-Host "CREATE-FAILED rv=$($r.ReturnValue)"; exit 1 }
Write-Host "STARTED pid=$($r.ProcessId)"
