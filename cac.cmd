@echo off
where pwsh >nul 2>&1 && (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0cac.ps1" %*
    exit /b %ERRORLEVEL%
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0cac.ps1" %*
