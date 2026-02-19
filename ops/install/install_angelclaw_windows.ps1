# ============================================================================
# AngelClaw AGI Guardian -- Windows Client Installer (V7.0.0)
#
# Installs ANGELNODE (lightweight agent) natively with Python.
# NO Docker required. Connects to your AngelClaw Cloud server.
# Auto-installs Python and Git via winget if missing.
#
# ONE-LINE INSTALL (PowerShell as Administrator):
#   irm https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.ps1 | iex
#
# WITH SERVER URL:
#   $env:ANGELCLAW_CLOUD_URL="http://YOUR-SERVER:8500"; irm https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.ps1 | iex
#
# Environment variable overrides:
#   ANGELCLAW_CLOUD_URL   Cloud server URL     (prompted if not set)
#   ANGELCLAW_TENANT_ID   Tenant identifier    (default: default)
#   ANGELCLAW_INSTALL_DIR Install directory     (default: C:\AngelClaw)
#   ANGELCLAW_BRANCH      Git branch           (default: main)
#   ANGELCLAW_FORCE       Force clean reinstall (set to "true")
# ============================================================================

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
$InstallDir = if ($env:ANGELCLAW_INSTALL_DIR)  { $env:ANGELCLAW_INSTALL_DIR }  else { "C:\AngelClaw" }
$TenantId   = if ($env:ANGELCLAW_TENANT_ID)    { $env:ANGELCLAW_TENANT_ID }    else { "default" }
$CloudUrl   = if ($env:ANGELCLAW_CLOUD_URL)    { $env:ANGELCLAW_CLOUD_URL }    else { "" }
$Branch     = if ($env:ANGELCLAW_BRANCH)        { $env:ANGELCLAW_BRANCH }       else { "main" }
$ForceClean = ($env:ANGELCLAW_FORCE -eq "true")

$Repo = "https://github.com/Senior3514/AngelClaw.git"
$TotalSteps = 7
$script:CurrentStep = 0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step {
    param([string]$msg)
    $script:CurrentStep++
    Write-Host ""
    Write-Host "[$script:CurrentStep/$TotalSteps] $msg" -ForegroundColor Cyan
}
function Write-Ok   { param([string]$msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "  [!]  $msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$msg) Write-Host "  [X]  $msg" -ForegroundColor Red }

function Refresh-Path {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath    = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path    = "$machinePath;$userPath"
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   AngelClaw AGI Guardian -- Windows Installer"   -ForegroundColor Cyan
Write-Host "   V7.0.0 -- Singularity (Native Python Agent)"      -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  No Docker required. Lightweight ANGELNODE agent." -ForegroundColor Gray

# ---------------------------------------------------------------------------
# Step 1: Pre-flight
# ---------------------------------------------------------------------------
Write-Step "Pre-flight validation..."

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Err "This installer must be run as Administrator."
    Write-Host "    Right-click PowerShell -> Run as Administrator"
    exit 1
}
Write-Ok "Running as Administrator."

# Prompt for Cloud URL if not set
if (-not $CloudUrl) {
    Write-Host ""
    Write-Host "  Enter your AngelClaw Cloud server URL." -ForegroundColor Yellow
    Write-Host "  (This is the Linux server running the full stack)" -ForegroundColor Gray
    Write-Host "  Example: http://203.0.113.50:8500" -ForegroundColor Gray
    Write-Host ""
    $CloudUrl = Read-Host "  Cloud URL"
    if (-not $CloudUrl) {
        $CloudUrl = "http://127.0.0.1:8500"
        Write-Warn "No URL entered. Using localhost (http://127.0.0.1:8500)."
    }
}

Write-Host ""
Write-Host "  Cloud URL    : $CloudUrl"
Write-Host "  Tenant ID    : $TenantId"
Write-Host "  Install dir  : $InstallDir"

# ---------------------------------------------------------------------------
# Step 2: Check / Install Git
# ---------------------------------------------------------------------------
Write-Step "Checking Git..."

$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitCmd) {
    Write-Warn "Git is not installed. Installing via winget..."
    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $wingetCmd) {
        Write-Err "winget is not available. Please install Git manually:"
        Write-Host "  https://git-scm.com/download/win"
        exit 1
    }
    winget install --id Git.Git --accept-source-agreements --accept-package-agreements --silent
    Refresh-Path
    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if (-not $gitCmd) {
        $gitPaths = @(
            "$env:ProgramFiles\Git\cmd",
            "${env:ProgramFiles(x86)}\Git\cmd",
            "$env:LOCALAPPDATA\Programs\Git\cmd"
        )
        foreach ($p in $gitPaths) {
            if (Test-Path "$p\git.exe") {
                $env:Path = "$p;$env:Path"
                break
            }
        }
        $gitCmd = Get-Command git -ErrorAction SilentlyContinue
        if (-not $gitCmd) {
            Write-Err "Git installed but not in PATH. Close and reopen PowerShell, then re-run."
            exit 1
        }
    }
    Write-Ok "Git installed."
} else {
    Write-Ok "Git found."
}

# ---------------------------------------------------------------------------
# Step 3: Check / Install Python
# ---------------------------------------------------------------------------
Write-Step "Checking Python..."

# Temporarily allow errors (Windows 10 Store aliases write to stderr and crash strict mode)
$savedEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"

$pyCmd = $null
foreach ($name in @("python", "python3")) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -and $cmd.Source -notmatch "WindowsApps") {
        $ver = cmd /c "$name --version" 2>&1
        if ("$ver" -match "Python 3\.(1[1-9]|[2-9]\d)") {
            $pyCmd = $name
            break
        }
    }
}

$ErrorActionPreference = $savedEAP

if (-not $pyCmd) {
    Write-Warn "Python 3.11+ not found. Installing via winget..."
    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $wingetCmd) {
        Write-Err "winget is not available. Install Python 3.12+ manually:"
        Write-Host "  https://www.python.org/downloads/"
        exit 1
    }
    winget install --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements --silent
    Refresh-Path
    # Try common Python paths
    $pyPaths = @(
        "$env:LOCALAPPDATA\Programs\Python\Python312",
        "$env:LOCALAPPDATA\Programs\Python\Python312\Scripts",
        "$env:ProgramFiles\Python312",
        "$env:ProgramFiles\Python312\Scripts"
    )
    foreach ($p in $pyPaths) {
        if (Test-Path $p) {
            $env:Path = "$p;$env:Path"
        }
    }
    $savedEAP2 = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    foreach ($name in @("python", "python3")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source -and $cmd.Source -notmatch "WindowsApps") {
            $testVer = cmd /c "$name --version" 2>&1
            if ("$testVer" -match "Python 3") { $pyCmd = $name; break }
        }
    }
    $ErrorActionPreference = $savedEAP2
    if (-not $pyCmd) {
        Write-Err "Python installed but not in PATH. Close and reopen PowerShell, then re-run."
        exit 1
    }
    Write-Ok "Python installed."
} else {
    $pyVer = & $pyCmd --version 2>&1
    Write-Ok "Python found: $pyVer"
}

# ---------------------------------------------------------------------------
# Step 4: Clone or update repo
# ---------------------------------------------------------------------------
Write-Step "Setting up AngelClaw at $InstallDir..."

if ($ForceClean -and (Test-Path $InstallDir)) {
    Write-Warn "Force flag set -- removing existing installation..."
    # Stop any running ANGELNODE first
    Get-Process -Name "uvicorn" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $InstallDir
}

if (Test-Path "$InstallDir\.git") {
    Write-Ok "Existing installation found -- pulling latest..."
    Push-Location $InstallDir
    try {
        git fetch origin 2>&1 | Out-Null
        git checkout $Branch 2>&1 | Out-Null
        git pull origin $Branch
        Write-Ok "Repository updated."
    } catch {
        Write-Err "Failed to update repository: $_"
        exit 1
    } finally {
        Pop-Location
    }
} else {
    if (Test-Path $InstallDir) {
        Write-Warn "Directory exists but is not a git repo -- removing and re-cloning..."
        Remove-Item -Recurse -Force $InstallDir
    }
    Write-Host "  Cloning repository..." -ForegroundColor Gray
    git clone --branch $Branch $Repo $InstallDir 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Public clone failed -- repo may be private."
        $GhUser  = if ($env:GH_USER)  { $env:GH_USER }  else { Read-Host "  GitHub username" }
        $GhToken = if ($env:GH_TOKEN) { $env:GH_TOKEN } else { Read-Host "  GitHub PAT (token)" }
        $AuthRepo = "https://${GhUser}:${GhToken}@github.com/Senior3514/AngelClaw.git"
        git clone --branch $Branch $AuthRepo $InstallDir
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Failed to clone repository. Check credentials."
            exit 1
        }
    }
    Write-Ok "Repository cloned."
}

# ---------------------------------------------------------------------------
# Step 5: Create venv and install dependencies
# ---------------------------------------------------------------------------
Write-Step "Installing Python dependencies..."

$venvDir = Join-Path $InstallDir "venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"
$venvPip = Join-Path $venvDir "Scripts\pip.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "  Creating virtual environment..." -ForegroundColor Gray
    & $pyCmd -m venv $venvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to create virtual environment."
        exit 1
    }
}
Write-Ok "Virtual environment ready."

Write-Host "  Installing packages (this may take a minute)..." -ForegroundColor Gray
Push-Location $InstallDir
try {
    & $venvPip install --quiet -e . 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        & $venvPip install -e .
        if ($LASTEXITCODE -ne 0) {
            throw "pip install failed"
        }
    }
    Write-Ok "Dependencies installed."
} catch {
    Write-Err "Failed to install dependencies: $_"
    exit 1
} finally {
    Pop-Location
}

# ---------------------------------------------------------------------------
# Step 6: Write config and start ANGELNODE
# ---------------------------------------------------------------------------
Write-Step "Configuring and starting ANGELNODE..."

# Create logs directory
$logDir = Join-Path $InstallDir "logs"
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Generate a unique agent ID for this machine
$agentId = "win-" + ($env:COMPUTERNAME).ToLower()

# Write a start script
$startScript = Join-Path $InstallDir "start_angelnode.ps1"
$startContent = @"
# AngelClaw ANGELNODE -- Auto-generated start script
`$env:ANGELGRID_CLOUD_URL = "$CloudUrl"
`$env:ANGELGRID_TENANT_ID = "$TenantId"
`$env:ANGELGRID_SYNC_INTERVAL = "60"
`$env:ANGELNODE_AGENT_ID = "$agentId"
`$env:ANGELNODE_POLICY_FILE = "$InstallDir\angelnode\config\default_policy.json"
`$env:ANGELNODE_CATEGORY_DEFAULTS_FILE = "$InstallDir\angelnode\config\category_defaults.json"
`$env:ANGELNODE_LOG_FILE = "$logDir\decisions.jsonl"

Set-Location "$InstallDir"
& "$venvDir\Scripts\uvicorn.exe" angelnode.core.server:app --host 127.0.0.1 --port 8400
"@
Set-Content -Path $startScript -Value $startContent -Encoding UTF8
Write-Ok "Start script written to $startScript"

# Set env vars and start ANGELNODE in background
$env:ANGELGRID_CLOUD_URL = $CloudUrl
$env:ANGELGRID_TENANT_ID = $TenantId
$env:ANGELGRID_SYNC_INTERVAL = "60"
$env:ANGELNODE_AGENT_ID = $agentId
$env:ANGELNODE_POLICY_FILE = "$InstallDir\angelnode\config\default_policy.json"
$env:ANGELNODE_CATEGORY_DEFAULTS_FILE = "$InstallDir\angelnode\config\category_defaults.json"
$env:ANGELNODE_LOG_FILE = "$logDir\decisions.jsonl"

# Stop any existing ANGELNODE
$existingJobs = Get-Process -Name "uvicorn" -ErrorAction SilentlyContinue
if ($existingJobs) {
    Write-Warn "Stopping existing ANGELNODE process..."
    $existingJobs | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Start ANGELNODE in background
$uvicornExe = Join-Path $venvDir "Scripts\uvicorn.exe"
Start-Process -FilePath $uvicornExe `
    -ArgumentList "angelnode.core.server:app --host 127.0.0.1 --port 8400" `
    -WorkingDirectory $InstallDir `
    -WindowStyle Hidden
Write-Ok "ANGELNODE started (port 8400, agent: $agentId)"

# Register Windows Scheduled Task for auto-start on boot
$taskName = "AngelClaw-ANGELNODE"
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$startScript`"" `
    -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Write-Ok "Auto-start registered (runs on boot as $taskName)"

# ---------------------------------------------------------------------------
# Step 7: Health check
# ---------------------------------------------------------------------------
Write-Step "Verifying ANGELNODE health..."

Write-Host "  Waiting for startup..." -ForegroundColor Gray
Start-Sleep -Seconds 5

$healthy = $false
for ($attempt = 1; $attempt -le 5; $attempt++) {
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:8400/health" -TimeoutSec 5
        $healthy = $true
        break
    } catch {
        if ($attempt -lt 5) {
            Write-Host "  Retry $attempt/5..." -ForegroundColor Gray
            Start-Sleep -Seconds 3
        }
    }
}

if ($healthy) {
    Write-Ok "ANGELNODE is healthy!"
} else {
    Write-Warn "Health check failed -- agent may still be starting."
    Write-Host "    Check manually: curl http://127.0.0.1:8400/health"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "   AngelClaw ANGELNODE -- Installed!"              -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Install dir  : $InstallDir"
Write-Host "  Agent ID     : $agentId"
Write-Host "  Tenant ID    : $TenantId"
Write-Host "  Cloud URL    : $CloudUrl"
Write-Host "  ANGELNODE    : http://127.0.0.1:8400"
Write-Host ""
Write-Host "  Auto-start   : Enabled (Windows Scheduled Task)" -ForegroundColor Green
Write-Host "  No Docker    : Running natively with Python" -ForegroundColor Green
Write-Host ""
Write-Host "  Useful commands:"
Write-Host "    curl http://127.0.0.1:8400/health        # health check"
Write-Host "    curl http://127.0.0.1:8400/status        # agent status"
Write-Host "    Get-ScheduledTask -TaskName AngelClaw*    # check auto-start"
Write-Host ""
Write-Host "  Start/Stop manually:"
Write-Host "    & `"$startScript`"                         # start"
Write-Host "    Stop-Process -Name uvicorn                # stop"
Write-Host ""
Write-Host "  Dashboard (on your server):"
Write-Host "    $CloudUrl/ui"
Write-Host ""
Write-Host "  Uninstall:"
Write-Host "    & `"$InstallDir\ops\install\uninstall_angelclaw_windows.ps1`""
Write-Host ""
Write-Host "  AngelClaw V7.0.0 -- Singularity" -ForegroundColor Cyan
Write-Host "  Guardian angel, not gatekeeper." -ForegroundColor Cyan
Write-Host ""
