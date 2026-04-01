@echo off
setlocal
cd /d "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
set "ERR=%ERRORLEVEL%"

if %ERR% neq 0 (
    echo.
    echo Installation failed with exit code %ERR%.
    pause
)
exit /b %ERR%
