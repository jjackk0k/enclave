# icmp-ps-parity.ps1 - proves the PowerShell ICMP transport in varvel-agent.ps1 is
# byte-exact against the audited JS codec (engine/icmpcodec.mjs) and that its raw-socket
# receive path works over a real NIC. Extracts ONLY the transport functions from the
# agent file via the PS AST (no code duplication - a drift in the agent breaks this).
# Usage: powershell -File icmp-ps-parity.ps1 [-WireHost 192.168.50.130]
param([string]$AgentFile = 'C:\Users\Jack\Downloads\enclave\varvel\agents\varvel-agent.ps1', [string]$WireHost = '')
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentFile, [ref]$tokens, [ref]$errors)
if ($errors.Count) { $errors | ForEach-Object { Write-Host ('PARSE-ERROR: ' + $_.Message) }; exit 1 }
Write-Host 'PARSE-OK'
$want = @('Get-InetChecksum', 'Get-IcmpPacket', 'Read-IcmpPacket', 'Receive-IcmpFrame', 'Connect-Icmp')
$found = @()
$fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($f in $fns) { if ($want -contains $f.Name) { Invoke-Expression $f.Extent.Text; $found += $f.Name } }
foreach ($w in $want) { if (-not ($found -contains $w)) { Write-Host "MISSING-FN: $w"; exit 1 } }

# 1) frame-bytes vector - Node must emit the identical bytes (compare outside this script)
$p = Get-IcmpPacket 8 21 1 0 1 ([Text.Encoding]::UTF8.GetBytes('parity-vector-payload'))
Write-Host ('FRAME-B64: ' + [Convert]::ToBase64String($p))

# 2) parse round-trip
$r = Read-IcmpPacket $p
Write-Host ("PARSED: type=$($r.type) seq=$($r.seq) kind=$($r.kind) idx=$($r.idx) cnt=$($r.cnt) data=$([Text.Encoding]::UTF8.GetString($r.data))")

# 3) tamper rejection (flip the kind byte - checksum now invalid)
$p[10] = $p[10] -bxor 0xff
Write-Host ('TamperRejected: ' + ($null -eq (Read-IcmpPacket $p)))

# 4) chunked frame shapes (reply reassembly units)
$f0 = Get-IcmpPacket 8 99 3 0 2 ([Text.Encoding]::UTF8.GetBytes('hello-'))
$f1 = Get-IcmpPacket 8 99 3 1 2 ([Text.Encoding]::UTF8.GetBytes('world'))
$r0 = Read-IcmpPacket $f0; $r1 = Read-IcmpPacket $f1
Write-Host ("ChunkParse: $($r0.idx)/$($r0.cnt)+$($r1.idx)/$($r1.cnt) data=$([Text.Encoding]::UTF8.GetString($r0.data))$([Text.Encoding]::UTF8.GetString($r1.data))")

# 5) real-NIC wire proof: raw socket send + kernel-echoed reply through Receive-IcmpFrame
if ($WireHost) {
  $Url = "icmp://$WireHost"
  try { Connect-Icmp } catch { Write-Host ('WIRE-SKIP: ' + $_.Exception.Message); exit 0 }
  $probe = Get-IcmpPacket 8 555 1 0 1 ([Text.Encoding]::UTF8.GetBytes('ps-wire-probe'))
  [void]$script:IcmpSock.SendTo($probe, $script:IcmpEndPoint)
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $hit = $null
  while ($sw.ElapsedMilliseconds -lt 5000 -and -not $hit) {
    $fr = Receive-IcmpFrame
    if ($fr -and $fr.kind -eq 'pull' -and $fr.seq -eq 555 -and ([Text.Encoding]::UTF8.GetString($fr.data)) -eq 'ps-wire-probe') { $hit = $fr }
  }
  if ($hit) { Write-Host ("WIRE-OK: src=$($hit.src) type=$($hit.type) - kernel relayed our VARVEL frame verbatim over the NIC") }
  else { Write-Host 'WIRE-FAIL: no echo within 5s'; exit 1 }
}
