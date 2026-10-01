@echo off
title EchoRisk AI Server
echo ===================================================
echo           Starting EchoRisk AI Server
echo ===================================================
echo [info] Backend: Python Flask (backend/)
echo [info] Frontend: Templates and static UI (frontend/)
echo [info] Opening browser at http://localhost:5000 ...
echo [info] Press Ctrl+C to stop the server.
echo.

:: Clean up unnecessary temporary/redundant files
if exist ".env.example" del /f /q ".env.example" 2>nul
if exist "cleanup.bat" del /f /q "cleanup.bat" 2>nul
if exist "backend\.env.example" del /f /q "backend\.env.example" 2>nul

:: Open browser automatically
start http://localhost:5000

:: Run with Python
python app.py

pause
