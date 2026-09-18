# check-agent-ps.ps1 - ASCII purity + PS parser check for varvel-agent.ps1 (lesson 18:
# never inline this through bash - the shell eats $vars).
$b = [IO.File]::ReadAllBytes('C:\Users\Jack\Downloads\enclave\varvel\agents\varvel-agent.ps1')
$nonascii = ($b | Where-Object { $_ -gt 127 } | Measure-Object).Count
$t = $null; $e = $null
[void][System.Management.Automation.Language.Parser]::ParseFile('C:\Users\Jack\Downloads\enclave\varvel\agents\varvel-agent.ps1', [ref]$t, [ref]$e)
Write-Output ('NONASCII=' + $nonascii + ' PARSEERRORS=' + $e.Count)
if ($e.Count) { $e | ForEach-Object { Write-Output ('  ERR: ' + $_.Message) } }
