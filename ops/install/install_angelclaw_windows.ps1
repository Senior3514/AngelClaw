# ============================================================================
# AngelClaw AGI Guardian -- Windows ANGELNODE Installer (V2.0.0)
#
# Installs the ANGELNODE agent only, connecting to a remote AngelClaw Cloud.
# Requires Docker Desktop for Windows.
# Connects to Angel Legion: 10-agent swarm with 7 specialized sentinels.
#
# Usage (PowerShell as Administrator):
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\install_angelclaw_windows.ps1 -CloudUrl "http://YOUR-VPS-IP:8500"
#
# Parameters:
#   -CloudUrl    Cloud API URL       (default: http://your-cloud-server:8500)
#   -TenantId    Tenant identifier   (default: default)
#   -InstallDir  Install directory   (default: C:\AngelClaw)
#   -Branch      Git branch          (default: main)
#   -Force       Force clean reinstall (removes existing install first)
#
# Example connecting to VPS at 168.231.110.18:
#   .\install_angelclaw_windows.ps1 -CloudUrl http://168.231.110.18:8500
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

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   AngelClaw AGI Guardian -- Windows Installer"   -ForegroundColor Cyan
Write-Host "   V2.0.0 -- Angel Legion"                        -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# Step 1: Pre-flight validation
# ---------------------------------------------------------------------------
Write-Step "Pre-flight validation..."

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warn "Not running as Administrator. Some operations may fail."
    Write-Host "    Tip: Right-click PowerShell -> Run as Administrator"
}

if ($CloudUrl -eq "http://your-cloud-server:8500") {
    Write-Warn "Using default CloudUrl placeholder."
    Write-Host "    Pass -CloudUrl to specify your VPS address."
}

Write-Ok "Pre-flight checks passed."

# ---------------------------------------------------------------------------
# Step 2: Check Docker Desktop
# ---------------------------------------------------------------------------
Write-Step "Checking Docker Desktop..."

$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if (-not $dockerCmd) {
    Write-Err "Docker is not installed or not in PATH."
    Write-Host ""
    Write-Host "  Please install Docker Desktop for Windows:"
    Write-Host "  https://docs.docker.com/desktop/install/windows-install/"
    Write-Host ""
    exit 1
}

$dockerVer = docker --version 2>&1
Write-Ok "Docker found: $dockerVer"

# Check Docker is running
try {
    docker info *>$null
    Write-Ok "Docker daemon is running."
} catch {
    Write-Err "Docker daemon is not running. Please start Docker Desktop."
    exit 1
}

# ---------------------------------------------------------------------------
# Step 3: Check docker compose
# ---------------------------------------------------------------------------
Write-Step "Checking docker compose..."

$dcCmd = $null
try {
    docker compose version *>$null
    $composeVer = docker compose version 2>&1
    Write-Ok "docker compose found: $composeVer"
    $dcCmd = "docker compose"
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
# Step 4: Check git
# ---------------------------------------------------------------------------
Write-Step "Checking git..."

$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitCmd) {
    Write-Err "git is not installed."
    Write-Host "  Install from: https://git-scm.com/download/win"
    exit 1
}
Write-Ok "git found."

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
        git fetch origin
        git checkout $Branch
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
    # Start only the angelnode service (not cloud/ollama -- those run on the VPS)
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
Write-Host "  Access the Cloud dashboard (on your VPS):"
Write-Host "    Open browser: $CloudUrl/ui"
Write-Host ""
Write-Host "  AngelClaw V2.0.0 -- Angel Legion" -ForegroundColor Cyan
Write-Host "  Guardian angel, not gatekeeper." -ForegroundColor Cyan
Write-Host ""
