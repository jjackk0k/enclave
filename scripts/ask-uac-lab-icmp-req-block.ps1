# ask-uac-lab-icmp-req-block.ps1 - triggers the UAC prompt for the type-8 block rule.
$r = Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\Users\Jack\Downloads\enclave\scripts\add-lab-icmp-req-block.ps1' -Wait -PassThru
Write-Host ('elevated process exited: ' + $r.ExitCode)
