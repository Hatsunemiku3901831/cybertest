@echo off
setlocal
cd /d "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_windows.ps1" %*
set "exit_code=%ERRORLEVEL%"

echo.
if not "%exit_code%"=="0" (
  echo Install script finished with errors. Exit code: %exit_code%
) else (
  echo Install script finished.
)
pause
exit /b %exit_code%
