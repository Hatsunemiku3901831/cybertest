@echo off
setlocal
cd /d "%~dp0"

set "skip_pause=0"
for %%A in (%*) do (
  if /I "%%~A"=="-Detect" set "skip_pause=1"
  if /I "%%~A"=="-DryRun" set "skip_pause=1"
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_windows.ps1" %*
set "exit_code=%ERRORLEVEL%"

echo.
if not "%exit_code%"=="0" (
  echo Install script finished with errors. Exit code: %exit_code%
) else (
  echo Install script finished.
)
if "%skip_pause%"=="0" pause
exit /b %exit_code%
