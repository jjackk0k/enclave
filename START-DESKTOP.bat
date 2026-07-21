@echo off
title Enclave desktop
cd /d "%~dp0desktop"
where node >nul 2>nul || ( echo Node.js 18+ required from https://nodejs.org & pause & exit /b 1 )
if not exist node_modules ( echo First run - installing the desktop shell ^(one-time^)... & call npm install --no-audit --no-fund )
echo Launching Enclave...
call npm start
