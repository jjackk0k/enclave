@echo off
title Enclave  -  secure AI console  (keep this window open)
cd /d "%~dp0"
echo(
echo   ============================================================
echo      ENCLAVE  -  secure AI console for security professionals
echo   ============================================================
echo(

where node >nul 2>nul || (
  echo   ERROR: Node.js 18+ is required.  Install it from https://nodejs.org and retry.
  echo(
  pause
  exit /b 1
)

echo   Detecting model backends (the server auto-attaches to the best one)...
where claude >nul 2>nul && (echo     [+] Claude CLI detected) || (echo     [-] Claude CLI not found)
if exist "%USERPROFILE%\.kimicode\config.json" (echo     [+] Kimi / k3 login detected  ^(used automatically once you're on the K3 subscription^)) else (echo     [-] Kimi / k3 not configured)
echo(
echo   The exact model that attached is shown in the banner just below.
echo   A browser tab opens in a few seconds.
echo(
echo   TO STOP:  close this window, or double-click  STOP-ENCLAVE.bat
echo(
echo   ------------------------------------------------------------

start "" powershell -NoProfile -Command "Start-Sleep 3; Start-Process 'http://localhost:8977/app.html'"
node server.mjs

echo(
echo   Enclave server stopped.  (Run STOP-ENCLAVE.bat if any sealed containers remain.)
pause
