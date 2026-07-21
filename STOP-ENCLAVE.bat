@echo off
title Enclave  -  stop
cd /d "%~dp0"
echo(
echo   Stopping the Enclave console (localhost:8977) and tearing down sealed containers...
echo(

REM --- stop whatever is listening on port 8977 (the server) ---
set _hit=0
for /f "tokens=5" %%p in ('netstat -ano ^| findstr /r /c:"TCP.*:8977 .*LISTENING"') do (
  taskkill /pid %%p /f >nul 2>nul && (echo     [+] stopped server (pid %%p) & set _hit=1)
)
if "%_hit%"=="0" echo     [-] no server was running on :8977

REM --- remove any sealed per-session containers + the egress broker ---
where docker >nul 2>nul && (
  set _n=0
  for /f %%c in ('docker ps -aq --filter "name=enclave-" 2^>nul') do ( docker rm -f %%c >nul 2>nul & set _n=1 )
  if defined _n (echo     [+] removed sealed enclave containers) else (echo     [-] no enclave containers to remove)
)

echo(
echo   Done.  Localhost is off.
timeout /t 3 >nul
