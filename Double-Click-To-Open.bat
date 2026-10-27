@echo off
title Nexora Website Preview
cd /d "%~dp0"
echo ========================================================
echo   Launching Nexora Digital Studio Website...
echo   No installation or setup needed!
echo ========================================================
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0server.ps1"
if %errorlevel% neq 0 (
    echo.
    echo If PowerShell is restricted, trying alternative...
    pause
)
pause
