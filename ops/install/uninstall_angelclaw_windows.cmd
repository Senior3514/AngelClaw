@echo off
setlocal enabledelayedexpansion
:: AngelClaw AGI Guardian -- Windows Uninstaller (V8.2.0)

set "INSTALL_DIR=C:\AngelClaw"

echo.
echo ================================================
echo    AngelClaw -- Windows Uninstaller
echo ================================================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [X] Run as Administrator.
    pause
    exit /b 1
)

echo [1/3] Stopping ANGELNODE...
taskkill /f /im uvicorn.exe >nul 2>&1
echo  [OK] Stopped.

echo.
echo [2/3] Removing auto-start task...
schtasks /delete /tn "AngelClaw-ANGELNODE" /f >nul 2>&1
echo  [OK] Task removed.

echo.
echo [3/3] Removing install directory...
if exist "%INSTALL_DIR%" (
    rmdir /s /q "%INSTALL_DIR%"
    echo  [OK] %INSTALL_DIR% removed.
) else (
    echo  [!] Not found -- skipping.
)

echo.
echo ================================================
echo    AngelClaw has been uninstalled.
echo ================================================
echo.
echo  To reinstall (CMD as Admin):
echo    curl -fsSL -o %%TEMP%%\install.cmd https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.cmd ^&^& %%TEMP%%\install.cmd
echo.
pause
