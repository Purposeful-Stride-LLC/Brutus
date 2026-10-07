@echo off
title BRUTUS Security Scanner - Console Launcher
echo ============================================================
echo    BRUTUS SECURITY SCANNER
echo         COMPREHENSIVE ANALYSIS TOOL
echo ============================================================
echo.
python "%~dp0brutus_runner.py" %*
if errorlevel 1 (
    echo.
    echo *** ERROR: Analysis failed. Check Python and dependencies. ***
)
pause
