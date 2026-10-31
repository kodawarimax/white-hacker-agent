@echo off
rem Display text is ASCII-only on purpose (cmd.exe parses this file before any codepage change).
setlocal

echo ============================================================================
echo   AI White Hacker Agent - static pattern security audit (Windows)
echo   Read-only. No data is sent externally. Report is created as HTML.
echo ============================================================================
echo.

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%scripts\Run_Windows_Audit.ps1"

if not "%~1"=="" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -TargetPath "%~1"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"
)

echo.
pause
