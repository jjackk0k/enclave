@echo off
title Spark Chat
set HOST=%1
if "%HOST%"=="" set /p HOST=Spark IP/hostname:
set /p MODE=Server type [o]llama or [v]llama/openai (o/v, default o):
if /i "%MODE%"=="v" (start "Spark Chat" cmd /k python "C:\Users\Jack\Downloads\enclave\spark-chat.py" %HOST% --port 8000) else (start "Spark Chat" cmd /k python "C:\Users\Jack\Downloads\enclave\spark-chat.py" %HOST% --ollama)
