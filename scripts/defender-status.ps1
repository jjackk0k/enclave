# defender-status.ps1 — Jack's host Defender config snapshot (breach test context). Pure ASCII.
$cs = Get-MpComputerStatus
Write-Output ('RTP=' + $cs.RealTimeProtectionEnabled + ' CloudDelivered=' + $cs.AMCloudDeliveredProtectionEnabled + ' BehaviorMon=' + $cs.BehaviorMonitorEnabled + ' PUA=' + $cs.PUAProtection + ' QuickScanAge(h)=' + [math]::Round(($cs.QuickScanAge).TotalHours,1))
$p = Get-MpPreference
Write-Output ('ExclPaths=' + (($p.ExclusionPath) -join ';') + ' | ExclProc=' + (($p.ExclusionProcess) -join ';') + ' | MAPSReporting=' + $p.MAPSReporting + ' | SubmitSamples=' + $p.SubmitSamplesConsent)
