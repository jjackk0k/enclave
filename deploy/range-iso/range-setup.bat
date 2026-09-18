@echo off
rem range-setup.bat — runs during specialize as SYSTEM (from the answer-file CD).
rem Plants the agent files, then hands the heavy lifting to range-tune.ps1.
set SRC=%~dp0
mkdir C:\Windows\Temp 2>nul
echo %DATE% %TIME% range-setup start > C:\Windows\Temp\range-setup.log
copy /y "%SRC%va-boot.ps1" C:\Windows\Temp\ >> C:\Windows\Temp\range-setup.log 2>&1
copy /y "%SRC%varvel-agent.ps1" C:\Windows\Temp\ >> C:\Windows\Temp\range-setup.log 2>&1
copy /y "%SRC%varvel-agent.bat" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\" >> C:\Windows\Temp\range-setup.log 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -File "%SRC%range-tune.ps1" >> C:\Windows\Temp\range-setup.log 2>&1
echo %DATE% %TIME% range-setup done >> C:\Windows\Temp\range-setup.log
