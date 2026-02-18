# ============================================================================
# AngelClaw AGI Guardian -- Windows ANGELNODE Installer (V2.2.1)
#
# Installs the ANGELNODE agent (client) connecting to your AngelClaw Cloud
# server. Auto-installs Docker Desktop and Git via winget if missing.
#
# ONE-LINE INSTALL (PowerShell as Administrator):
#   Set-ExecutionPolicy Bypass -Scope Process -Force; iwr -Uri 'https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.ps1' -OutFile "$env:TEMP\install_angelclaw.ps1"; & "$env:TEMP\install_angelclaw.ps1" -CloudUrl 'http://YOUR-VPS-IP:8500'
#
# LOCAL INSTALL (if repo already cloned):
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\ops\install\install_angelclaw_windows.ps1 -CloudUrl "http://YOUR-VPS-IP:8500"
#
# Parameters:
#   -CloudUrl    Cloud API URL       (default: http://your-cloud-server:8500)
#   -TenantId    Tenant identifier   (default: default)
#   -InstallDir  Install directory   (default: C:\AngelClaw)
#   -Branch      Git branch          (default: main)
#   -Force       Force clean reinstall (removes existing install first)
# ============================================================================

param(
    [string]$CloudUrl   = "http://your-cloud-server:8500",
    [string]$TenantId   = "default",
    [string]$InstallDir = "C:\AngelClaw",
    [string]$Branch     = "main",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$Repo = "https://github.com/Senior3514/AngelClaw.git"
$TotalSteps = 8
$script:CurrentStep = 0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step {
    param([string]$msg)
    $script:CurrentStep++
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
Write-Host "   V2.2.1 -- Angel Legion"                        -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# Step 1: Pre-flight validation
# ---------------------------------------------------------------------------
Write-Step "Pre-flight validation..."

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Err "This installer must be run as Administrator."
    Write-Host "    Right-click PowerShell -> Run as Administrator"
    exit 1
}

if ($CloudUrl -eq "http://your-cloud-server:8500") {
    Write-Warn "No -CloudUrl specified. Using placeholder."
    Write-Host "    Pass -CloudUrl to specify your server address."
}

Write-Ok "Pre-flight checks passed."

# ---------------------------------------------------------------------------
# Step 2: Check/Install Git
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
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to install Git via winget. Install manually:"
        Write-Host "  https://git-scm.com/download/win"
        exit 1
    }
    Refresh-Path
    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if (-not $gitCmd) {
        Write-Warn "Git installed but not in PATH yet."
        # Try common install paths
        $gitPaths = @(
            "$env:ProgramFiles\Git\cmd",
            "${env:ProgramFiles(x86)}\Git\cmd",
            "$env:LOCALAPPDATA\Programs\Git\cmd"
        )
        foreach ($p in $gitPaths) {
            if (Test-Path "$p\git.exe") {
                $env:Path = "$p;$env:Path"
                Write-Ok "Found Git at $p"
                break
            }
        }
        $gitCmd = Get-Command git -ErrorAction SilentlyContinue
        if (-not $gitCmd) {
            Write-Err "Git installed but cannot be found. Please close and reopen PowerShell, then re-run this script."
            exit 1
        }
    }
    Write-Ok "Git installed successfully."
} else {
    Write-Ok "Git found."
}

# ---------------------------------------------------------------------------
# Step 3: Check/Install Docker Desktop
# ---------------------------------------------------------------------------
Write-Step "Checking Docker Desktop..."

$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if (-not $dockerCmd) {
    Write-Warn "Docker Desktop is not installed. Installing via winget..."
    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $wingetCmd) {
        Write-Err "winget is not available. Please install Docker Desktop manually:"
        Write-Host "  https://docs.docker.com/desktop/install/windows-install/"
        exit 1
    }
    winget install --id Docker.DockerDesktop --accept-source-agreements --accept-package-agreements --silent
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to install Docker Desktop via winget. Install manually:"
        Write-Host "  https://docs.docker.com/desktop/install/windows-install/"
        exit 1
    }
    Refresh-Path
    # Try common Docker paths
    $dockerPaths = @(
        "$env:ProgramFiles\Docker\Docker\resources\bin",
        "$env:ProgramFiles\Docker\Docker"
    )
    foreach ($p in $dockerPaths) {
        if (Test-Path "$p\docker.exe") {
            $env:Path = "$p;$env:Path"
            break
        }
    }
    $dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $dockerCmd) {
        Write-Ok "Docker Desktop installed."
        Write-Host ""
        Write-Host "  ================================================" -ForegroundColor Yellow
        Write-Host "  Docker Desktop was just installed." -ForegroundColor Yellow
        Write-Host "  Please RESTART your computer, then:" -ForegroundColor Yellow
        Write-Host "    1. Open Docker Desktop and wait for it to start" -ForegroundColor Yellow
        Write-Host "    2. Re-run this installer" -ForegroundColor Yellow
        Write-Host "  ================================================" -ForegroundColor Yellow
        Write-Host ""
        exit 0
    }
    Write-Ok "Docker Desktop installed."
}

$dockerVer = docker --version 2>&1
Write-Ok "Docker found: $dockerVer"

# Check Docker is running
$dockerRunning = $false
try {
    $null = docker info 2>&1
    if ($LASTEXITCODE -eq 0) { $dockerRunning = $true }
} catch {}

if (-not $dockerRunning) {
    Write-Warn "Docker Desktop is not running. Attempting to start..."
    $dockerDesktop = "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"
    if (Test-Path $dockerDesktop) {
        Start-Process $dockerDesktop
        Write-Host "  Waiting for Docker to start (up to 60s)..." -ForegroundColor Gray
        $waited = 0
        while ($waited -lt 60) {
            Start-Sleep -Seconds 5
            $waited += 5
            try {
                $null = docker info 2>&1
                if ($LASTEXITCODE -eq 0) { $dockerRunning = $true; break }
            } catch {}
            Write-Host "  Waiting... ($waited`s)" -ForegroundColor Gray
        }
    }
    if (-not $dockerRunning) {
        Write-Err "Docker Desktop is not running. Please start it manually and re-run this script."
        exit 1
    }
}
Write-Ok "Docker daemon is running."

# ---------------------------------------------------------------------------
# Step 4: Check docker compose
# ---------------------------------------------------------------------------
Write-Step "Checking docker compose..."

$dcCmd = $null
try {
    $null = docker compose version 2>&1
    if ($LASTEXITCODE -eq 0) {
        $composeVer = docker compose version 2>&1
        Write-Ok "docker compose found: $composeVer"
        $dcCmd = "docker compose"
    }
} catch {}

if (-not $dcCmd) {
    $dockerComposeCmd = Get-Command docker-compose -ErrorAction SilentlyContinue
    if ($dockerComposeCmd) {
        $composeVer = docker-compose --version 2>&1
        Write-Ok "docker-compose found: $composeVer"
        $dcCmd = "docker-compose"
    }
}

if (-not $dcCmd) {
    Write-Err "docker compose is not available."
    Write-Host "  Docker Desktop should include docker compose. Please update Docker Desktop."
    exit 1
}

# ---------------------------------------------------------------------------
# Step 5: Clone or update repo
# ---------------------------------------------------------------------------
Write-Step "Setting up AngelClaw at $InstallDir..."

if ($Force -and (Test-Path $InstallDir)) {
    Write-Warn "Force flag set -- removing existing installation..."
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
    git clone --branch $Branch $Repo $InstallDir
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to clone repository."
        exit 1
    }
    Write-Ok "Repository cloned."
}

# ---------------------------------------------------------------------------
# Step 6: Write ANGELNODE config
# ---------------------------------------------------------------------------
Write-Step "Writing ANGELNODE configuration..."

$configDir = Join-Path $InstallDir "ops\config"
if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
}

$configFile = Join-Path $configDir "angelclaw.env"
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$configContent = @"
# AngelClaw AGI Guardian -- generated by installer on $timestamp
ANGELCLAW_CLOUD_URL=$CloudUrl
ANGELCLAW_TENANT_ID=$TenantId
ANGELCLAW_SYNC_INTERVAL=60
LLM_ENABLED=false
"@

Set-Content -Path $configFile -Value $configContent -Encoding UTF8
Write-Ok "Config written to $configFile"

# ---------------------------------------------------------------------------
# Step 7: Build and start ANGELNODE container
# ---------------------------------------------------------------------------
Write-Step "Building and starting ANGELNODE container..."

$opsDir = Join-Path $InstallDir "ops"
Push-Location $opsDir
try {
    if ($dcCmd -eq "docker compose") {
        docker compose up -d --build angelnode
    } else {
        docker-compose up -d --build angelnode
    }
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose returned exit code $LASTEXITCODE"
    }
    Write-Ok "ANGELNODE container started."
} catch {
    Write-Err "Failed to start container: $_"
    Write-Host "  Try running manually:"
    Write-Host "    cd $opsDir"
    Write-Host "    docker compose up -d --build angelnode"
} finally {
    Pop-Location
}

# ---------------------------------------------------------------------------
# Step 8: Health check with retries
# ---------------------------------------------------------------------------
Write-Step "Verifying ANGELNODE health..."

Write-Host "  Waiting for startup..." -ForegroundColor Gray
Start-Sleep -Seconds 8

$healthy = $false
for ($attempt = 1; $attempt -le 3; $attempt++) {
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:8400/health" -TimeoutSec 5
        $healthy = $true
        break
    } catch {
        if ($attempt -lt 3) {
            Write-Host "  Retry $attempt/3..." -ForegroundColor Gray
            Start-Sleep -Seconds 5
        }
    }
}

if ($healthy) {
    Write-Ok "ANGELNODE is healthy (port 8400)"
} else {
    Write-Warn "Health check failed -- container may still be starting."
    Write-Host "    Check: curl http://127.0.0.1:8400/health"
    Write-Host "    Logs:  docker logs angelclaw-angelnode-1"
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
Write-Host "  Config       : $configFile"
Write-Host "  Tenant ID    : $TenantId"
Write-Host "  Cloud URL    : $CloudUrl"
Write-Host "  ANGELNODE    : http://127.0.0.1:8400"
Write-Host ""
Write-Host "  Useful commands:"
Write-Host "    docker ps                              # check container"
Write-Host "    docker logs angelclaw-angelnode-1 -f   # follow logs"
Write-Host "    curl http://127.0.0.1:8400/status      # agent status"
Write-Host ""
Write-Host "  Access the Cloud dashboard (on your server):"
Write-Host "    Open browser: $CloudUrl/ui"
Write-Host ""
Write-Host "  AngelClaw V2.2.1 -- Angel Legion" -ForegroundColor Cyan
Write-Host "  Guardian angel, not gatekeeper." -ForegroundColor Cyan
Write-Host ""
