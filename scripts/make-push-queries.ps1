# make-push-queries.ps1 -Token <tok> -AgentId <id> -TaskId <tid> [-Size 1400]
# Prints the EXACT query strings the agent's Invoke-IcmpPush would send (AST-extracted
# functions from the live agent file), one per line, to %TEMP%\push-queries.txt.
param([string]$Token, [string]$AgentId, [string]$TaskId, [int]$Size = 1400)
$ErrorActionPreference = 'Stop'
$AgentFile = 'C:\Users\Jack\Downloads\enclave\varvel\agents\varvel-agent.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentFile, [ref]$tokens, [ref]$errors)
if ($errors.Count) { Write-Host 'PARSE-FAIL'; exit 1 }
$want = @('Get-HmacHex', 'Get-EncodedQuery', 'ConvertTo-B32')
$fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
$found = @()
foreach ($f in $fns) { if ($want -contains $f.Name) { Invoke-Expression $f.Extent.Text; $found += $f.Name } }
foreach ($w in $want) { if (-not ($found -contains $w)) { Write-Host "MISSING-FN: $w"; exit 1 } }
$B32_CHARS = '0123456789abcdefghijklmnopqrstuv'
$DnsDomain = 'ax.sim'
$Body = [Text.Encoding]::UTF8.GetBytes('q' * $Size)
$chunkSize = 96
$chunks = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt $Body.Length; $i += $chunkSize) {
  $len = [Math]::Min($chunkSize, $Body.Length - $i)
  $chunk = New-Object byte[] $len
  [Array]::Copy($Body, $i, $chunk, 0, $len)
  $chunks.Add([Convert]::ToBase64String($chunk))
}
$n = $chunks.Count
$out = @()
$seq = 0
for ($i = 0; $i -lt $n; $i++) {
  $seq++
  $d = $chunks[$i]
  $h = Get-HmacHex $Token ($AgentId + ':' + $seq + ':' + $TaskId + ':' + $i + ':' + $n + ':' + $d)
  $out += (Get-EncodedQuery ([ordered]@{ a = $AgentId; s = $seq; h = $h; t = $TaskId; k = 'push'; i = $i; n = $n; d = $d }) $DnsDomain)
}
[IO.File]::WriteAllLines("$env:TEMP\push-queries.txt", $out)
Write-Host ('WROTE ' + $n + ' queries')
