# detor-names.ps1 — resolve recent threat IDs to names. PS left-typed: prepend '' for string context.
Get-MpThreat -ErrorAction SilentlyContinue | Select-Object -First 8 | ForEach-Object {
  Write-Output ('' + $_.ThreatID + '  ' + $_.ThreatName + '  sev:' + $_.SeverityID)
}
