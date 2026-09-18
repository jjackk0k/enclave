# guest-icmp-matrix.ps1 - wire-shape matrix probe. Sends ONE type-8 VC probe (seq 4242),
# then logs every VARVEL frame the guest raw socket receives for 20s. Self-logging
# (Add-Content) so it can run fully detached via WMI. PURE ASCII ONLY (PS 5.1 reads
# BOM-less files as ANSI - UTF-8 punctuation corrupts tokenization).
param(
  [string]$AgentFile = 'C:\Windows\System32\agentbox\varvel-agent.ps1',
  [string]$Dst = '192.168.50.1',
  [string]$LogPath = 'C:\Windows\Temp\icmp-matrix.log',
  [int]$ListenMs = 20000
)
$ErrorActionPreference = 'Stop'
function Log([string]$m) { Add-Content -Path $LogPath -Value $m -Encoding Ascii }
Log ('MATRIX-START ' + (Get-Date).ToString('HH:mm:ss'))
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentFile, [ref]$tokens, [ref]$errors)
if ($errors.Count) { Log 'AGENTFILE-PARSE-FAIL'; exit 1 }
$want = @('Get-InetChecksum', 'Get-IcmpPacket', 'Connect-Icmp', 'Read-IcmpPacket', 'Receive-IcmpFrame')
$fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
$found = @()
foreach ($f in $fns) { if ($want -contains $f.Name) { Invoke-Expression $f.Extent.Text; $found += $f.Name } }
foreach ($w in $want) { if (-not ($found -contains $w)) { Log "MISSING-FN: $w"; exit 1 } }
$Url = "icmp://$Dst"
try { Connect-Icmp } catch { Log ('SOCK-FAIL: ' + $_.Exception.Message); exit 1 }
$pkt = Get-IcmpPacket 8 4242 1 0 1 ([Text.Encoding]::UTF8.GetBytes('matrix-guest-probe'))
try { [void]$script:IcmpSock.SendTo($pkt, $script:IcmpEndPoint); Log 'PROBE-SENT type=8 seq=4242' } catch { Log ('SEND-FAIL: ' + $_.Exception.Message); exit 1 }
$sw = [Diagnostics.Stopwatch]::StartNew()
$seen = 0
while ($sw.ElapsedMilliseconds -lt $ListenMs) {
  $f = Receive-IcmpFrame
  if ($null -eq $f) { continue }
  $seen++
  Log ("FRAME type=" + $f.type + " kind=" + $f.kind + " seq=" + $f.seq + " dlen=" + $f.data.Length + " src=" + $f.src)
}
Log ("MATRIX-DONE seen=" + $seen)
