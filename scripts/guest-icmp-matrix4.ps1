# guest-icmp-matrix4.ps1 - type-scan listener: logs ANY inbound ICMP packet carrying
# the VC magic, regardless of ICMP type (the standard parser drops non-0/8 BEFORE
# logging - which blinded all earlier probes). Decides the reply shape: if type
# 13/14/42 frames arrive while type 0 does not, the kernel's echo machinery was the
# filter and replies get reframed to a type it does not claim. PURE ASCII ONLY.
param(
  [string]$AgentFile = 'C:\Windows\System32\agentbox\varvel-agent.ps1',
  [string]$LogPath = 'C:\Windows\Temp\icmp-matrix4.log',
  [int]$ListenMs = 15000
)
$ErrorActionPreference = 'Stop'
function Log([string]$m) { Add-Content -Path $LogPath -Value $m -Encoding Ascii }
Log ('MATRIX4-START ' + (Get-Date).ToString('HH:mm:ss'))
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentFile, [ref]$tokens, [ref]$errors)
if ($errors.Count) { Log 'AGENTFILE-PARSE-FAIL'; exit 1 }
$want = @('Get-InetChecksum', 'Connect-Icmp')
$fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
$found = @()
foreach ($f in $fns) { if ($want -contains $f.Name) { Invoke-Expression $f.Extent.Text; $found += $f.Name } }
foreach ($w in $want) { if (-not ($found -contains $w)) { Log "MISSING-FN: $w"; exit 1 } }
$Url = 'icmp://192.168.50.1'
try { Connect-Icmp } catch { Log ('SOCK-FAIL: ' + $_.Exception.Message); exit 1 }
$sw = [Diagnostics.Stopwatch]::StartNew()
$seen = 0
while ($sw.ElapsedMilliseconds -lt $ListenMs) {
  $buf = New-Object byte[] 65535
  $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
  $n = 0
  try { $n = $script:IcmpSock.ReceiveFrom($buf, [ref]$remote) } catch { continue }
  if ($n -lt 29) { continue }
  $data = New-Object byte[] $n
  [Array]::Copy($buf, 0, $data, 0, $n)
  if (($data[0] -shr 4) -eq 4) {
    $ihl = ($data[0] -band 0x0F) * 4
    if ($ihl -ge 20 -and $ihl -le $n) { $s = New-Object byte[] ($n - $ihl); [Array]::Copy($data, $ihl, $s, 0, ($n - $ihl)); $data = $s }
  }
  if ($data.Length -lt 21) { continue }
  if ((Get-InetChecksum $data) -ne 0) { continue }
  if ($data[8] -ne 0x56 -or $data[9] -ne 0x43) { continue }
  $seen++
  $seq = ([int]$data[6] * 256) + [int]$data[7]
  Log ("FRAME type=" + [int]$data[0] + " code=" + [int]$data[1] + " echoseq=" + $seq + " dlen=" + ($data.Length - 21) + " src=" + $remote.Address.ToString())
}
Log ("MATRIX4-DONE seen=" + $seen)
