@echo off
chcp 65001 > nul
setlocal

echo ============================================================================
echo   AI White Hacker Agent - Windows クライアントPC / サーバー セキュリティ監査
echo   (読み取り専用・外部送信ゼロ・100点満点監査レポート＆保守提案書自動生成)
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
