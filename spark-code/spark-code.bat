@echo off
rem ============================================================
rem  spark-code.bat -- launch the Spark Code terminal agent.
rem
rem  Works from ANY folder: the agent operates in the folder you
rem  launch it from. Flags pass straight through, e.g.:
rem      spark-code.bat                  interactive
rem      spark-code.bat --yolo           auto-approve writes/shell
rem      spark-code.bat --resume-last    reopen the latest session
rem      spark-code.bat --effort high    bigger answer budget
rem
rem  Prefers the Kimi Work managed Python (stdlib-only is enough);
rem  falls back to any python on PATH.
rem ============================================================
setlocal
set "SC_HOME=%~dp0"
set "PY=C:\Users\Jack\AppData\Roaming\kimi-desktop\daimon-share\daimon\runtime\python\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"
set "PYTHONPATH=%SC_HOME%;%PYTHONPATH%"
"%PY%" -m spark_code %*
endlocal
