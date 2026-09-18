# test-timeout-harness.ps1 - replicates the agent's new shell-case flow EXACTLY on the
# host with a short timeout: Start-Process cmd with redirected output, poll, taskkill,
# read via FileShare, marker. Prints the resulting string for inspection.
param([int]$TimeoutSec = 5, [string]$Cmd = 'ping -n 20 127.0.0.1')
$timeoutSec = $TimeoutSec
$tmpOut = Join-Path $env:TEMP ('va-task-' + [Guid]::NewGuid().ToString('N') + '.log')
$p = Start-Process cmd.exe -ArgumentList '/d','/c',"$Cmd > `"$tmpOut`" 2>&1" -WindowStyle Hidden -PassThru
$sw = [Diagnostics.Stopwatch]::StartNew()
while (-not $p.HasExited -and $sw.Elapsed.TotalSeconds -lt $timeoutSec) { Start-Sleep -Milliseconds 250 }
$killed = $false
if (-not $p.HasExited) {
  $killed = $true
  try { & taskkill /PID $p.Id /T /F 2>&1 | Out-Null } catch {}
  Start-Sleep -Milliseconds 500
}
$out = ''
try {
  $fs = [IO.File]::Open($tmpOut, 'Open', 'Read', 'ReadWrite')
  $sr = New-Object IO.StreamReader($fs)
  $out = $sr.ReadToEnd()
  $sr.Close(); $fs.Close()
} catch {}
try { Remove-Item $tmpOut -Force -ErrorAction SilentlyContinue } catch {}
if ($killed) { $out = "TASK TIMEOUT after ${timeoutSec}s - process tree killed`r`n" + $out }
Write-Host ('KILLED=' + $killed + ' OUTLEN=' + $out.Length)
Write-Host '---'
Write-Host $out.Trim()
