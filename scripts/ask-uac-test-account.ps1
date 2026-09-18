# ask-uac-test-account.ps1 — self-elevating launcher for add-test-account.ps1.
# Jack runs THIS (normal shell); Windows shows ONE UAC prompt; he clicks Yes.
Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\Users\Jack\Downloads\enclave\scripts\add-test-account.ps1'
