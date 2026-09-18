# guest-icmp-listen.ps1 — sends ONE governed pull, then LISTENS on the guest's raw
# socket and prints every VARVEL frame seen for 15s. Answers the last unobserved link:
# does the channel's echo-reply (even the EMPTY idle reply) reach a guest raw socket?
param(
  [string]$AgentFile = 'C:\Windows\System32\agentbox\varvel-agent.ps1',
  [string]$AgentId = 'probe000000',
  [string]$Token = '00',
  [string]$Dst = '192.168.50.1',
  [int]$ListenMs = 15000
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
try { [void]$script:IcmpSock.SendTo($pkt, $script:IcmpEndPoint); Write-Host 'PULL-SENT seq=1' } catch { Write-Host ('SEND-FAIL: ' + $_.Exception.Message); exit 1 }
$sw = [Diagnostics.Stopwatch]::StartNew()
$seen = 0
while ($sw.ElapsedMilliseconds -lt $ListenMs) {
  $f = Receive-IcmpFrame
  if ($null -eq $f) { continue }
  $seen++
  Write-Host ("FRAME kind=" + $f.kind + " type=" + $f.type + " seq=" + $f.seq + " idx=" + $f.idx + "/" + $f.cnt + " src=" + $f.src + " dlen=" + $f.data.Length)
}
Write-Host ("LISTEN-DONE seen=" + $seen)
