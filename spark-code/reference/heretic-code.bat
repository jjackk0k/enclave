@echo off
rem ============================================================
rem  heretic-code.bat -- launch the Crush terminal agent backed
rem  by the Spark's Heretic model, agent lane port 8080.
rem
rem  Run from ANY folder: the agent works in the folder you
rem  launch it from. Pass any crush flags through, e.g.:
rem      heretic-code.bat            interactive, asks before writes/shell
rem      heretic-code.bat --yolo     interactive, auto-approves everything
rem      heretic-code.bat run "hi"   one-shot, non-interactive
rem ============================================================
setlocal

rem --- 1. Make sure the agent lane is reachable via SSH tunnel ---
curl -s --max-time 3 -o nul http://127.0.0.1:8080/v1/models
if errorlevel 1 (
    echo [heretic-code] Agent lane not reachable. Opening SSH tunnel to Spark...
    start "spark-tunnel" /min ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -N -L 8080:127.0.0.1:8080 -L 8081:127.0.0.1:8081 varvel@gx10-d094.local
    rem wait up to ~15s for the tunnel to come up; ping = portable 1s sleep
    for /l %%i in (1,1,15) do (
        ping -n 2 127.0.0.1 >nul
        curl -s --max-time 2 -o nul http://127.0.0.1:8080/v1/models && goto tunnel_ok
    )
    echo [heretic-code] ERROR: agent lane unreachable after 15s.
    echo   The SSH tunnel opened, but the model server did not answer.
    echo   Most likely: llama-server on the Spark is down or busy -
    echo   model swap or benchmark run - try again in a few minutes.
    echo   Otherwise check: ssh varvel@gx10-d094.local works without a password.
    exit /b 1
)

:tunnel_ok
rem --- 2. Launch crush in the current folder ---
"C:\Users\Jack\spark-tools\crush.exe" %*
endlocal
