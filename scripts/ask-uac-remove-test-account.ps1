# ask-uac-remove-test-account.ps1 — self-elevating launcher for remove-test-account.ps1.
Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\Users\Jack\Downloads\enclave\scripts\remove-test-account.ps1'
