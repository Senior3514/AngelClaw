@echo off
setlocal enabledelayedexpansion
:: ============================================================================
:: AngelClaw AGI Guardian -- Windows Client Installer (V3.0.0)
:: Native Python ANGELNODE agent. No Docker required.
::
:: INSTALL (CMD as Administrator):
::   curl -fsSL -o %TEMP%\install.cmd https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.cmd && %TEMP%\install.cmd
:: ============================================================================

set "INSTALL_DIR=C:\AngelClaw"
set "BRANCH=main"
set "REPO=https://github.com/Senior3514/AngelClaw.git"
set "TENANT_ID=default"
set "STEP=0"

echo.
echo ================================================
echo    AngelClaw AGI Guardian -- Windows Installer
echo    V3.0.0 -- Dominion (Native Python Agent)
echo ================================================
echo.
echo    No Docker required. Lightweight agent.
echo.

:: ---------------------------------------------------------------------------
:: Admin check
:: ---------------------------------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [X] This installer must be run as Administrator.
    echo      Right-click CMD -^> Run as Administrator
    pause
    exit /b 1
)
echo  [OK] Running as Administrator.

:: ---------------------------------------------------------------------------
:: Cloud URL
:: ---------------------------------------------------------------------------
if defined ANGELCLAW_CLOUD_URL (
    set "CLOUD_URL=%ANGELCLAW_CLOUD_URL%"
) else (
    echo.
    echo  Enter your AngelClaw Cloud server URL.
    echo  Example: http://203.0.113.50:8500
    echo.
    set /p "CLOUD_URL=  Cloud URL: "
)
if "!CLOUD_URL!"=="" set "CLOUD_URL=http://127.0.0.1:8500"

if defined ANGELCLAW_TENANT_ID set "TENANT_ID=%ANGELCLAW_TENANT_ID%"

echo.
echo  Cloud URL   : !CLOUD_URL!
echo  Tenant ID   : !TENANT_ID!
echo  Install dir : %INSTALL_DIR%
echo.

:: ---------------------------------------------------------------------------
:: [1/6] Git
:: ---------------------------------------------------------------------------
set /a STEP+=1
echo [%STEP%/6] Checking Git...

where git >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Git not found. Installing via winget...
    winget install --id Git.Git --accept-source-agreements --accept-package-agreements --silent
    set "PATH=%ProgramFiles%\Git\cmd;%PATH%"
    where git >nul 2>&1
    if !errorlevel! neq 0 (
        echo  [X] Git install failed. Install manually: https://git-scm.com/download/win
        pause
        exit /b 1
    )
    echo  [OK] Git installed.
) else (
    echo  [OK] Git found.
)

:: ---------------------------------------------------------------------------
:: [2/6] Python
:: ---------------------------------------------------------------------------
set /a STEP+=1
echo.
echo [%STEP%/6] Checking Python...

set "PYTHON="

:: Check real python (skip WindowsApps Store stubs)
for %%P in (python.exe python3.exe) do (
    if not defined PYTHON (
        for /f "tokens=*" %%i in ('where %%P 2^>nul') do (
            echo %%i | findstr /i "WindowsApps" >nul
            if !errorlevel! neq 0 (
                set "PYTHON=%%i"
            )
        )
    )
)

if defined PYTHON (
    echo  [OK] Python found: !PYTHON!
) else (
    echo  [!] Python not found. Installing Python 3.12 via winget...
    winget install --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements --silent
    :: Add to PATH
    set "PATH=%LOCALAPPDATA%\Programs\Python\Python312;%LOCALAPPDATA%\Programs\Python\Python312\Scripts;%ProgramFiles%\Python312;%ProgramFiles%\Python312\Scripts;%PATH%"
    for %%P in (python.exe python3.exe) do (
        if not defined PYTHON (
            for /f "tokens=*" %%i in ('where %%P 2^>nul') do (
                echo %%i | findstr /i "WindowsApps" >nul
                if !errorlevel! neq 0 (
                    set "PYTHON=%%i"
                )
            )
        )
    )
    if not defined PYTHON (
        echo  [X] Python installed but not in PATH. Close this window, reopen CMD as Admin, re-run.
        pause
        exit /b 1
    )
    echo  [OK] Python 3.12 installed.
)

:: ---------------------------------------------------------------------------
:: [3/6] Clone repo
:: ---------------------------------------------------------------------------
set /a STEP+=1
echo.
echo [%STEP%/6] Setting up AngelClaw at %INSTALL_DIR%...

if exist "%INSTALL_DIR%\.git" (
    echo  [OK] Existing installation found -- pulling latest...
    pushd "%INSTALL_DIR%"
    git pull origin %BRANCH%
    popd
    echo  [OK] Repository updated.
) else (
    if exist "%INSTALL_DIR%" (
        echo  [!] Directory exists but not a git repo -- removing...
        rmdir /s /q "%INSTALL_DIR%"
    )
    echo  Cloning repository...
    git clone --branch %BRANCH% %REPO% "%INSTALL_DIR%" 2>nul
    if !errorlevel! neq 0 (
        echo  [!] Public clone failed -- repo may be private.
        set /p "GH_USER=  GitHub username: "
        set /p "GH_TOKEN=  GitHub PAT (token): "
        git clone --branch %BRANCH% "https://!GH_USER!:!GH_TOKEN!@github.com/Senior3514/AngelClaw.git" "%INSTALL_DIR%"
        if !errorlevel! neq 0 (
            echo  [X] Clone failed. Check credentials.
            pause
            exit /b 1
        )
    )
    echo  [OK] Repository cloned.
)

:: ---------------------------------------------------------------------------
:: [4/6] Venv + install
:: ---------------------------------------------------------------------------
set /a STEP+=1
echo.
echo [%STEP%/6] Installing Python dependencies...

set "VENV=%INSTALL_DIR%\venv"
set "VENV_PYTHON=%VENV%\Scripts\python.exe"
set "VENV_PIP=%VENV%\Scripts\pip.exe"
set "VENV_UVICORN=%VENV%\Scripts\uvicorn.exe"

if not exist "%VENV_PYTHON%" (
    echo  Creating virtual environment...
    "!PYTHON!" -m venv "%VENV%"
    if !errorlevel! neq 0 (
        echo  [X] Failed to create venv.
        pause
        exit /b 1
    )
)
echo  [OK] Virtual environment ready.

echo  Installing packages (may take a minute)...
pushd "%INSTALL_DIR%"
"%VENV_PIP%" install --quiet -e . 2>nul
if %errorlevel% neq 0 (
    "%VENV_PIP%" install -e .
)
popd
echo  [OK] Dependencies installed.

:: ---------------------------------------------------------------------------
:: [5/6] Config + start
:: ---------------------------------------------------------------------------
set /a STEP+=1
echo.
echo [%STEP%/6] Configuring and starting ANGELNODE...

:: Create logs dir
if not exist "%INSTALL_DIR%\logs" mkdir "%INSTALL_DIR%\logs"

:: Agent ID from computer name
set "AGENT_ID=win-%COMPUTERNAME%"

:: Write start script
set "START_BAT=%INSTALL_DIR%\start_angelnode.cmd"
(
    echo @echo off
    echo set "ANGELGRID_CLOUD_URL=!CLOUD_URL!"
    echo set "ANGELGRID_TENANT_ID=!TENANT_ID!"
    echo set "ANGELGRID_SYNC_INTERVAL=60"
    echo set "ANGELNODE_AGENT_ID=!AGENT_ID!"
    echo set "ANGELNODE_POLICY_FILE=%INSTALL_DIR%\angelnode\config\default_policy.json"
    echo set "ANGELNODE_CATEGORY_DEFAULTS_FILE=%INSTALL_DIR%\angelnode\config\category_defaults.json"
    echo set "ANGELNODE_LOG_FILE=%INSTALL_DIR%\logs\decisions.jsonl"
    echo cd /d "%INSTALL_DIR%"
    echo "%VENV_UVICORN%" angelnode.core.server:app --host 127.0.0.1 --port 8400
) > "%START_BAT%"
echo  [OK] Start script: %START_BAT%

:: Kill any existing ANGELNODE
taskkill /f /im uvicorn.exe >nul 2>&1
timeout /t 2 /nobreak >nul

:: Set env vars and start in background
set "ANGELGRID_CLOUD_URL=!CLOUD_URL!"
set "ANGELGRID_TENANT_ID=!TENANT_ID!"
set "ANGELGRID_SYNC_INTERVAL=60"
set "ANGELNODE_AGENT_ID=!AGENT_ID!"
set "ANGELNODE_POLICY_FILE=%INSTALL_DIR%\angelnode\config\default_policy.json"
set "ANGELNODE_CATEGORY_DEFAULTS_FILE=%INSTALL_DIR%\angelnode\config\category_defaults.json"
set "ANGELNODE_LOG_FILE=%INSTALL_DIR%\logs\decisions.jsonl"

start "" /b /min cmd /c "cd /d "%INSTALL_DIR%" && "%VENV_UVICORN%" angelnode.core.server:app --host 127.0.0.1 --port 8400"
echo  [OK] ANGELNODE started (port 8400, agent: !AGENT_ID!)

:: Register auto-start via Scheduled Task
schtasks /delete /tn "AngelClaw-ANGELNODE" /f >nul 2>&1
schtasks /create /tn "AngelClaw-ANGELNODE" /tr "cmd /c \"%START_BAT%\"" /sc onstart /ru SYSTEM /rl HIGHEST /f >nul 2>&1
if %errorlevel% equ 0 (
    echo  [OK] Auto-start registered (runs on boot^)
) else (
    echo  [!] Could not register auto-start. Run manually: %START_BAT%
)

:: ---------------------------------------------------------------------------
:: [6/6] Health check
:: ---------------------------------------------------------------------------
set /a STEP+=1
echo.
echo [%STEP%/6] Verifying ANGELNODE health...

echo  Waiting for startup...
timeout /t 5 /nobreak >nul

set "HEALTHY=0"
for /l %%i in (1,1,5) do (
    if !HEALTHY! equ 0 (
        curl -sf --max-time 3 http://127.0.0.1:8400/health >nul 2>&1
        if !errorlevel! equ 0 (
            set "HEALTHY=1"
        ) else (
            echo  Retry %%i/5...
            timeout /t 3 /nobreak >nul
        )
    )
)

if %HEALTHY% equ 1 (
    echo  [OK] ANGELNODE is healthy!
) else (
    echo  [!] Health check failed -- agent may still be starting.
    echo      Check: curl http://127.0.0.1:8400/health
)

:: ---------------------------------------------------------------------------
:: Summary
:: ---------------------------------------------------------------------------
echo.
echo ================================================
echo    AngelClaw ANGELNODE -- Installed!
echo ================================================
echo.
echo  Install dir  : %INSTALL_DIR%
echo  Agent ID     : !AGENT_ID!
echo  Tenant ID    : !TENANT_ID!
echo  Cloud URL    : !CLOUD_URL!
echo  ANGELNODE    : http://127.0.0.1:8400
echo.
echo  Auto-start   : Enabled (Windows Scheduled Task)
echo  No Docker    : Running natively with Python
echo.
echo  Start/Stop:
echo    %START_BAT%
echo    taskkill /f /im uvicorn.exe
echo.
echo  Dashboard (on your server):
echo    !CLOUD_URL!/ui
echo.
echo  Default login: admin / fzMiSbDRGylsWrsaljMv7UxzrwdXCdTe
echo  Change the password immediately!
echo.
echo  ------------------------------------------------
echo  Talk to AngelClaw from CLI:
echo  ------------------------------------------------
echo.
echo  Chat (natural language):
echo    curl -X POST !CLOUD_URL!/api/v1/angelclaw/chat -H "Content-Type: application/json" -d "{\"tenantId\":\"!TENANT_ID!\",\"prompt\":\"Scan the system\"}"
echo.
echo  Agent health:
echo    curl http://127.0.0.1:8400/health
echo.
echo  Agent status:
echo    curl http://127.0.0.1:8400/status
echo.
echo  Cloud health:
echo    curl !CLOUD_URL!/health
echo.
echo  Example prompts:
echo    "Scan the system"
echo    "Show me threats"
echo    "Legion status"
echo    "Anti-tamper status"
echo    "Org overview"
echo    "Quarantine agent-001"
echo.
echo  AngelClaw V3.0.0 -- Dominion
echo  Guardian angel, not gatekeeper.
echo.
pause
