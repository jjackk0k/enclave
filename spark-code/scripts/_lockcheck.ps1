$root = 'C:\Users\Jack\Downloads\enclave\spark-code'
Write-Output "=== processes pointing into the project (these lock their own exe) ==="
Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like "$root*" } |
  Select-Object ProcessId, Name, ExecutablePath | Format-Table -AutoSize
Write-Output "=== lock test: can we copy spark-code.exe? (locked => error) ==="
try {
  Copy-Item (Join-Path $root 'spark-code.exe') "$env:TEMP\_sc_locktest.exe" -Force -ErrorAction Stop
  Write-Output "NOT LOCKED (copy succeeded; cleaning up)"
  Remove-Item "$env:TEMP\_sc_locktest.exe" -Force -ErrorAction SilentlyContinue
} catch {
  Write-Output "LOCKED by another process -> $($_.Exception.Message)"
}
