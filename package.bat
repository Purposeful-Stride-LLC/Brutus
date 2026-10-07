@echo off
title BRUTUS Portable Package Builder
echo ============================================================
echo    BRUTUS PORTABLE EXECUTABLE BUILDER
echo ============================================================
echo.

REM --- Require a real build toolchain; never fake an .exe by renaming .py ---
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo [!] PyInstaller is NOT installed - cannot build a real executable.
    echo     This builder will NOT produce a fake .exe.
    echo.
    echo     To build a real standalone Brutus executable, install PyInstaller:
    echo         python -m pip install pyinstaller
    echo     then re-run:  package.bat
    echo.
    pause
    exit /b 1
)

echo [*] PyInstaller found. Building a real standalone executable...
echo.
python -m PyInstaller --onefile --clean --noconfirm --name brutus ^
    --add-data "brutus_scope.txt;." ^
    --add-data "nova.ai;." ^
    brutus_runner.py
if errorlevel 1 (
    echo.
    echo *** BUILD FAILED. See the PyInstaller output above. ***
    pause
    exit /b 1
)

REM --- Stage supporting files alongside the exe so operators can edit the scope ---
copy /Y brutus_scope.txt dist\brutus_scope.txt >nul 2>&1
copy /Y nova.ai          dist\nova.ai          >nul 2>&1
copy /Y README.md        dist\README.txt       >nul 2>&1

echo.
echo ============================================================
echo Real package built: dist\brutus.exe
echo ============================================================
dir dist /b
echo.
echo Run:  dist\brutus.exe --demo
echo       dist\brutus.exe --ack --scope 127.0.0.1
pause
