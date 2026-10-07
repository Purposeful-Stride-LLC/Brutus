@echo off
title BRUTUS Service Scanner
echo ============================================================
echo    SERVICE PORT SCANNER (DEMO MODE)
echo ============================================================
echo.
python "%~dp0service_scanner.py" %*
if errorlevel 1 (
    echo.
    echo *** ERROR: Scanner failed. Check network permissions. ***
)
pause
