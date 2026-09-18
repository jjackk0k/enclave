# remove-test-account.ps1 — breach-test cleanup: delete the 'varvel-test' local user AND
# the cred file. Runs ELEVATED (launched by ask-uac-remove-test-account.ps1). Pure ASCII.
$ErrorActionPreference = 'SilentlyContinue'
Remove-LocalUser -Name 'varvel-test' -Confirm:$false
Remove-Item 'C:\Users\Jack\Downloads\enclave\scripts\test-account.cred.txt' -Force
Write-Output 'REMOVED varvel-test account and cred file (if they existed).'
Read-Host 'Press Enter to close'
