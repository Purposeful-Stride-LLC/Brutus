@echo off
title BRUTUS Rainbow Table Loader
echo ============================================================
echo    LOADING BREACH DATABASE (DEMO MODE)
echo ============================================================
echo.
python "%~dp0rainbow_table.py" %*
if errorlevel 1 (
    echo.
    echo *** ERROR: Failed to load breach database. ***
)
pause
