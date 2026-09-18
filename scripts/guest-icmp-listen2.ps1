# guest-icmp-listen2.ps1 - mirrors the NEW agent pull EXACTLY (Send-EchoProbe then the
# VC pull) and dumps every VARVEL frame for 15s. Splits wire-vs-agent: if the channel's
# type-0 reply shows up here, delivery works and the bug lives in the agent's receive
# path; if not, solicitation itself is still failing. PURE ASCII ONLY.
param(
  [string]$AgentFile = 'C:\Windows\System32\agentbox\varvel-agent.ps1',
  [string]$AgentId = 'probe000000',
  [string]$Token = '00',
  [string]$Dst = '192.168.50.1',
  [string]$LogPath = 'C:\Windows\Temp\icmp-listen2.log',
  [int]$ListenMs = 15000
)
$ErrorActionPreference = 'Stop'
function Log([string]$m) { Add-Content -Path $LogPath -Value $m -Encoding Ascii }
Log ('LISTEN2-START ' + (Get-Date).ToString('HH:mm:ss'))
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentFile, [ref]$tokens, [ref]$errors)
if ($errors.Count) { Log 'AGENTFILE-PARSE-FAIL'; exit 1 }
$want = @('Get-InetChecksum', 'Get-IcmpPacket', 'Connect-Icmp', 'Get-HmacHex', 'Get-EncodedQuery', 'ConvertTo-B32', 'Read-IcmpPacket', 'Receive-IcmpFrame', 'Send-EchoProbe')
$fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
$found = @()
foreach ($f in $fns) { if ($want -contains $f.Name) { Invoke-Expression $f.Extent.Text; $found += $f.Name } }
foreach ($w in $want) { if (-not ($found -contains $w)) { Log "MISSING-FN: $w"; exit 1 } }
$B32_CHARS = '0123456789abcdefghijklmnopqrstuv'
$script:Seq = 0
$Url = "icmp://$Dst"
try { Connect-Icmp } catch { Log ('SOCK-FAIL: ' + $_.Exception.Message); exit 1 }
$script:Seq = 1
Send-EchoProbe 1
Log 'PROBE-SENT seq=1'
$h = Get-HmacHex $Token ($AgentId + ':1:pull')
$q = Get-EncodedQuery ([ordered]@{ a = $AgentId; s = 1; h = $h }) 'ax.sim'
$pkt = Get-IcmpPacket 0 1 1 0 1 ([Text.Encoding]::UTF8.GetBytes($q))
try { [void]$script:IcmpSock.SendTo($pkt, $script:IcmpEndPoint); Log 'PULL-SENT seq=1' } catch { Log ('SEND-FAIL: ' + $_.Exception.Message); exit 1 }
$sw = [Diagnostics.Stopwatch]::StartNew()
$seen = 0
while ($sw.ElapsedMilliseconds -lt $ListenMs) {
  $f = Receive-IcmpFrame
  if ($null -eq $f) { continue }
  $seen++
  Log ("FRAME type=" + $f.type + " kind=" + $f.kind + " seq=" + $f.seq + " idx=" + $f.idx + "/" + $f.cnt + " src=" + $f.src + " dlen=" + $f.data.Length)
}
Log ("LISTEN2-DONE seen=" + $seen)
