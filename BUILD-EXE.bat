@echo off
title Build Enclave.exe
cd /d "%~dp0desktop"
where node >nul 2>nul || ( echo Node.js 18+ required from https://nodejs.org & pause & exit /b 1 )
if not exist node_modules ( echo Installing build tools ^(one-time, ~200MB^)... & call npm install --no-audit --no-fund )

echo Staging the sealed runtime...
if exist ".stage" rmdir /s /q ".stage"
robocopy "%~dp0." ".stage\enclave" /E /XD "%~dp0desktop" "%~dp0.git" "%~dp0.github" "%~dp0.enclave-live" "%~dp0workspaces" /NFL /NDL /NJH /NJS /NP >nul

echo Packaging Enclave.exe ^(takes a minute^)...
call npx @electron/packager . Enclave --platform=win32 --arch=x64 --out=dist --overwrite --extra-resource=.stage/enclave --ignore="(node_modules|\.stage|dist|\.git)"

echo.
echo ============================================================
echo   Done.  Your app:
echo   desktop\dist\Enclave-win32-x64\Enclave.exe
echo   ^(the whole Enclave-win32-x64 folder is the portable app^)
echo ============================================================
pause
