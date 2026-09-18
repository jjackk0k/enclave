# ask-uac-lab-icmp.ps1 — triggers the UAC prompt for the lab ICMP firewall rule.
$r = Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\Users\Jack\Downloads\enclave\scripts\add-lab-icmp-rule.ps1' -Wait -PassThru
Write-Host ('elevated process exited: ' + $r.ExitCode)
