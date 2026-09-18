# add-test-account.ps1 — breach-test prep (Jack-approved): create the throwaway local
# STANDARD user 'varvel-test' with a random 20-char password. Runs ELEVATED (launched by
# ask-uac-test-account.ps1; Jack clicks Yes once). Credential is written to
# scripts/test-account.cred.txt (his own profile ACLs) for the governed test harness and
# is DELETED by remove-test-account.ps1 after the test. Pure ASCII (PS 5.1 rule).
$ErrorActionPreference = 'Stop'
$name = 'varvel-test'
$pw = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ })
$sec = ConvertTo-SecureString $pw -AsPlainText -Force
if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $name -Confirm:$false }
New-LocalUser -Name $name -Password $sec -FullName 'VARVEL breach-test' -Description 'Throwaway account for the governed breach test. REMOVE AFTER with remove-test-account.ps1' | Out-Null
$credFile = 'C:\Users\Jack\Downloads\enclave\scripts\test-account.cred.txt'
Set-Content -Path $credFile -Value ($name + ' ' + $pw) -Encoding ASCII
Write-Output ('CREATED local user ' + $name + ' (standard user, random 20-char password)')
Write-Output ('Credential stored for the test harness: ' + $credFile)
Write-Output 'After the test, run ask-uac-remove-test-account.ps1 to delete the account AND the cred file.'
Read-Host 'Press Enter to close'
