@echo off
setlocal
set "ALLVM_SCRIPT=%~dp0tools\allvm.py"
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  py -3 "%ALLVM_SCRIPT%" %*
  exit /b %ERRORLEVEL%
)
where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  python "%ALLVM_SCRIPT%" %*
  exit /b %ERRORLEVEL%
)
echo ALLVM: Python 3.9 or newer was not found. 1>&2
exit /b 2
