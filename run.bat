@echo off
title EchoRisk AI Server
echo ===================================================
echo           Starting EchoRisk AI Server
echo ===================================================
echo [info] Backend: Python Flask (backend/)
echo [info] Frontend: Templates and static UI (frontend/)
echo [info] Opening browser at http://localhost:5000 ...
:: Prevent Python from generating __pycache__ folders
set PYTHONDONTWRITEBYTECODE=1

:: Open browser automatically
start "" http://localhost:5000

:: Run EchoRisk AI
python app.py

pause
