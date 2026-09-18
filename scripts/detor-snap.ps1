# detor-snap.ps1 — detoracle snapshot as a FILE (the cmd /c quoting path mangled the
# inline version). Same contract: one DETOR line, fail-closed pieces marked unreadable.
# NOTE: Get-MpThreatDetection needs admin; unelevated it reads as U (unknown) honestly.
$t = 'U'
try { $t = (Get-MpThreatDetection -ErrorAction Stop | Measure-Object).Count } catch {}
$d = 'U'
try { $d = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116} -MaxEvents 50 -ErrorAction Stop | Measure-Object).Count } catch {}
$b = 'U'
try { $b = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1117} -MaxEvents 50 -ErrorAction Stop | Measure-Object).Count } catch {}
$r = 0
$cs = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($cs -and $cs.RealTimeProtectionEnabled) { $r = 1 }
Write-Output ('DETOR T' + $t + ' D' + $d + ' B' + $b + ' R' + $r)
