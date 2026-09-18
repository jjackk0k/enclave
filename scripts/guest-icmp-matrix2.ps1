# guest-icmp-matrix2.ps1 - solicitation-keying probe. Sends PLAIN echo requests to
# addresses that should NOT answer (blackhole .254, directed broadcast .255), then
# logs every VARVEL frame for 15s. If the host bridge's type-0 replies (seq 4242/4243,
# sent from .1) ARRIVE, Windows echo state is NOT source-keyed and blackhole
# solicitation works. PURE ASCII ONLY.
param(
  [string]$AgentFile = 'C:\Windows\System32\agentbox\varvel-agent.ps1',
  [string]$LogPath = 'C:\Windows\Temp\icmp-matrix2.log',
  [int]$ListenMs = 15000
)
$ErrorActionPreference = 'Stop'
function Log([string]$m) { Add-Content -Path $LogPath -Value $m -Encoding Ascii }
Log ('MATRIX2-START ' + (Get-Date).ToString('HH:mm:ss'))
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentFile, [ref]$tokens, [ref]$errors)
if ($errors.Count) { Log 'AGENTFILE-PARSE-FAIL'; exit 1 }
$want = @('Get-InetChecksum', 'Connect-Icmp', 'Read-IcmpPacket', 'Receive-IcmpFrame')
$fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
$found = @()
foreach ($f in $fns) { if ($want -contains $f.Name) { Invoke-Expression $f.Extent.Text; $found += $f.Name } }
foreach ($w in $want) { if (-not ($found -contains $w)) { Log "MISSING-FN: $w"; exit 1 } }
$Url = 'icmp://192.168.50.1'
try { Connect-Icmp } catch { Log ('SOCK-FAIL: ' + $_.Exception.Message); exit 1 }
function Send-PlainProbe([string]$dst, [int64]$seq) {
  $pkt = New-Object byte[] 24
  $pkt[0] = 8; $pkt[1] = 0; $pkt[2] = 0; $pkt[3] = 0
  $pkt[4] = 0x56; $pkt[5] = 0x01
  $pkt[6] = [byte](($seq -shr 8) -band 0xff); $pkt[7] = [byte]($seq -band 0xff)
  $cs = Get-InetChecksum $pkt
  $pkt[2] = [byte](($cs -shr 8) -band 0xff); $pkt[3] = [byte]($cs -band 0xff)
  $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($dst), 0)
  try { [void]$script:IcmpSock.SendTo($pkt, $ep); return 'sent' } catch { return ('FAIL: ' + $_.Exception.Message) }
}
Log ('PROBE-254: ' + (Send-PlainProbe '192.168.50.254' 4242))
Log ('PROBE-255: ' + (Send-PlainProbe '192.168.50.255' 4243))
$sw = [Diagnostics.Stopwatch]::StartNew()
$seen = 0
while ($sw.ElapsedMilliseconds -lt $ListenMs) {
  $f = Receive-IcmpFrame
  if ($null -eq $f) { continue }
  $seen++
  Log ("FRAME type=" + $f.type + " kind=" + $f.kind + " seq=" + $f.seq + " dlen=" + $f.data.Length + " src=" + $f.src)
}
Log ("MATRIX2-DONE seen=" + $seen)
