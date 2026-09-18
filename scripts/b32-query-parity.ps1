# b32-query-parity.ps1 — proves the PS DNS/ICMP query encoding (ConvertTo-B32 +
# Get-EncodedQuery in varvel-agent.ps1) is byte-exact against the JS dnscodec.
# The DNS live-verify last week used the NODE sim-agent — this PS path has never
# been proven end-to-end. A drift here = the host's decodeQuery silently rejects
# every agent frame (exactly the 'checkins 0' symptom).
$AgentFile = 'C:\Users\Jack\Downloads\enclave\varvel\agents\varvel-agent.ps1'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($AgentFile, [ref]$tokens, [ref]$errors)
if ($errors.Count) { $errors | ForEach-Object { Write-Host ('PARSE-ERROR: ' + $_.Message) }; exit 1 }
$want = @('ConvertTo-B32', 'ConvertFrom-B32', 'Get-EncodedQuery')
$found = @()
$fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
foreach ($f in $fns) { if ($want -contains $f.Name) { Invoke-Expression $f.Extent.Text; $found += $f.Name } }
foreach ($w in $want) { if (-not ($found -contains $w)) { Write-Host "MISSING-FN: $w"; exit 1 } }
# ConvertTo-B32 reads the agent's SCRIPT-LEVEL constant (varvel-agent.ps1:124) — the AST
# extraction pulls functions only, so provide the same constant for the harness scope.
$B32_CHARS = '0123456789abcdefghijklmnopqrstuv'
$q = Get-EncodedQuery ([ordered]@{ a = 'abcdef123456'; s = 1; h = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' }) 'ax.sim'
Write-Host ('PS-QUERY: ' + $q)
