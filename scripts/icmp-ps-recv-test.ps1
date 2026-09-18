# icmp-ps-recv-test.ps1 — deterministic test of the AGENT'S RECEIVE PATH (no guest needed):
# extracts the agent's receive functions, opens the raw socket on 127.0.0.1, and listens.
# A companion sender (the python bridge) injects a synthetic kind='reply' frame — on
# loopback the kernel relays it to raw sockets (proven all day), so this exercises
# Receive-IcmpFrame + the reply filter for real.
param([int]$ListenMs = 6000)
$AgentFile = 'C:\Users\Jack\Downloads\enclave\varvel\agents\varvel-agent.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentFile, [ref]$tokens, [ref]$errors)
if ($errors.Count) { Write-Host 'PARSE-FAIL'; exit 1 }
$want = @('Connect-Icmp', 'Receive-IcmpFrame', 'Read-IcmpPacket', 'Get-IcmpPacket', 'Get-InetChecksum')
$fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
$found = @()
foreach ($f in $fns) { if ($want -contains $f.Name) { Invoke-Expression $f.Extent.Text; $found += $f.Name } }
foreach ($w in $want) { if (-not ($found -contains $w)) { Write-Host "MISSING-FN: $w"; exit 1 } }
$Url = 'icmp://127.0.0.1'
$script:Seq = 77
try { Connect-Icmp } catch { Write-Host ('SOCK-FAIL: ' + $_.Exception.Message); exit 1 }
Write-Host 'LISTENING seq=77'
$sw = [Diagnostics.Stopwatch]::StartNew()
$hit = 0
while ($sw.ElapsedMilliseconds -lt $ListenMs) {
  $f = Receive-IcmpFrame
  if ($null -eq $f) { continue }
  Write-Host ("FRAME kind=" + $f.kind + " type=" + $f.type + " seq=" + $f.seq + " src=" + $f.src + " data=" + [Text.Encoding]::UTF8.GetString($f.data))
  if ($f.kind -eq 'reply' -and $f.seq -eq [int64]$script:Seq) { $hit++; Write-Host 'REPLY-MATCH-OK' }
}
Write-Host ("DONE hit=" + $hit)
