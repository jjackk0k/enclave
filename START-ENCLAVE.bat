@echo off
title Enclave  -  secure AI console  (keep this window open)
cd /d "%~dp0"
echo(
echo   ============================================================
echo      ENCLAVE  -  secure AI console for security professionals
echo   ============================================================
echo(

where node >nul 2>nul || (
  echo   ERROR: Node.js was not found on your PATH.
  echo   Install Node 18+ from https://nodejs.org and run this again.
  echo(
  pause
  exit /b 1
)

where claude >nul 2>nul && (
  echo   Attaching to your Claude CLI.  Every tool call the AI makes will be
  echo   gated by the signed clearance of whoever you log in as.
) || (
  echo   NOTE: the 'claude' CLI was not found on PATH -- the console will run
  echo   in scripted demo mode.  Install Claude Code to test it live.
)
echo(
echo   A browser tab opens in a few seconds.  Keep THIS window open while you
echo   work; close it to stop the server.
echo(

start "" powershell -NoProfile -Command "Start-Sleep 3; Start-Process 'http://localhost:8977/app.html'"
node server.mjs

echo(
echo   Enclave server stopped.
pause
