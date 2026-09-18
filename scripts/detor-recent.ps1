# detor-recent.ps1 — newest Defender detections with timestamps + names (honest check:
# did anything fire during the P3 payload window?). Pure ASCII.
$e = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116} -MaxEvents 6 -ErrorAction SilentlyContinue
foreach ($x in $e) {
  $name = ($x.Properties[1].Value)
  Write-Output ($x.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + '  ' + $name)
}
Write-Output '---threat-list entries---'
try {
  Get-MpThreatDetection -ErrorAction Stop | Select-Object -First 6 | ForEach-Object {
    Write-Output ($_.LastThreatStatusChangeTime.ToString('yyyy-MM-dd HH:mm:ss') + '  ' + $_.ThreatID + '  action:' + $_.CurrentThreatExecutionStatus)
  }
} catch { Write-Output ('threat-list unreadable: ' + $_.Exception.Message) }
