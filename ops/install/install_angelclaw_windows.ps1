# ============================================================================
# AngelClaw AGI Guardian — Windows ANGELNODE Installer (V2.0.0)
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
#
# Example connecting to VPS at 168.231.110.18:
#   .\install_angelclaw_windows.ps1 -CloudUrl http://168.231.110.18:8500
# ============================================================================

param(
    [string]$CloudUrl   = "http://your-cloud-server:8500",
    [string]$TenantId   = "default",
    [string]$InstallDir = "C:\AngelClaw",
    [string]$Branch     = "main"
)

$ErrorActionPreference = "Stop"
$Repo = "https://github.com/Senior3514/AngelClaw.git"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step  { param($msg) Write-Host "[AngelClaw] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[!] $msg"  -ForegroundColor Yellow }
function Write-Err   { param($msg) Write-Host "[X] $msg"  -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   AngelClaw AGI Guardian — Windows Installer"     -ForegroundColor Cyan
Write-Host "   V2.0.0 — Angel Legion"                          -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# Step 1: Check Docker Desktop
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
# Step 2: Check docker-compose
# ---------------------------------------------------------------------------
Write-Step "Checking docker-compose..."

$hasCompose = $false
try {
    $composeVer = docker compose version 2>&1
    Write-Ok "docker compose found: $composeVer"
    $dcCmd = "docker compose"
    $hasCompose = $true
} catch {}

if (-not $hasCompose) {
    $dockerComposeCmd = Get-Command docker-compose -ErrorAction SilentlyContinue
    if ($dockerComposeCmd) {
        $composeVer = docker-compose --version 2>&1
        Write-Ok "docker-compose found: $composeVer"
        $dcCmd = "docker-compose"
        $hasCompose = $true
    }
}

if (-not $hasCompose) {
    Write-Err "docker-compose is not available."
    Write-Host "  Docker Desktop should include 'docker compose'. Please update Docker Desktop."
    exit 1
}

# ---------------------------------------------------------------------------
# Step 3: Check git
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
# Step 4: Clone or update repo
# ---------------------------------------------------------------------------
Write-Step "Setting up AngelClaw at $InstallDir..."

if (Test-Path "$InstallDir\.git") {
    Write-Step "Existing installation found — pulling latest..."
    Push-Location $InstallDir
    git fetch origin
    git checkout $Branch
    git pull origin $Branch
    Pop-Location
    Write-Ok "Repository updated."
} else {
    Write-Step "Cloning repository..."
    git clone --branch $Branch $Repo $InstallDir
    Write-Ok "Repository cloned."
}

# ---------------------------------------------------------------------------
# Step 5: Write ANGELNODE config
# ---------------------------------------------------------------------------
Write-Step "Writing ANGELNODE configuration..."

$configDir = "$InstallDir\ops\config"
if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
}

$configFile = "$configDir\angelclaw.env"
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$configContent = @"
# AngelClaw AGI Guardian environment — generated by installer on $timestamp
ANGELCLAW_CLOUD_URL=$CloudUrl
ANGELCLAW_TENANT_ID=$TenantId
ANGELCLAW_SYNC_INTERVAL=60
LLM_ENABLED=false
"@

Set-Content -Path $configFile -Value $configContent -Encoding UTF8
Write-Ok "Config written to $configFile"

# ---------------------------------------------------------------------------
# Step 6: Build and start ANGELNODE container
# ---------------------------------------------------------------------------
Write-Step "Building and starting ANGELNODE..."

Push-Location "$InstallDir\ops"

# Start only the angelnode service (not cloud/ollama — those run on the VPS)
if ($dcCmd -eq "docker compose") {
    docker compose up -d --build angelnode
} else {
    docker-compose up -d --build angelnode
}

Pop-Location
Write-Ok "ANGELNODE container started."

# ---------------------------------------------------------------------------
# Step 7: Health check
# ---------------------------------------------------------------------------
Write-Step "Waiting for ANGELNODE to become healthy..."
Start-Sleep -Seconds 10

try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:8400/health" -TimeoutSec 5
    Write-Ok "ANGELNODE is healthy (port 8400)"
} catch {
    Write-Warn "ANGELNODE health check failed — it may still be starting."
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "   AngelClaw ANGELNODE installed!"                  -ForegroundColor Green
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
Write-Host "  AngelClaw V2.0.0 — Angel Legion — guardian angel, not gatekeeper." -ForegroundColor Cyan
Write-Host ""
