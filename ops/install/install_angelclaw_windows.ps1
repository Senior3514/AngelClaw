# ============================================================================
# AngelClaw AGI Guardian -- Windows Full-Stack Installer (V3.0.0)
#
# Installs the COMPLETE AngelClaw stack (ANGELNODE + Cloud + Ollama) on
# Windows using Docker Desktop. Auto-installs Docker Desktop and Git via
# winget if missing.
#
# ONE-LINE INSTALL (PowerShell as Administrator):
#   irm https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.ps1 | iex
#
# CUSTOM TENANT (set env vars before running):
#   $env:ANGELCLAW_TENANT_ID="acme-corp"; irm https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.ps1 | iex
#
# LOCAL INSTALL (if repo already cloned):
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\ops\install\install_angelclaw_windows.ps1
#
# Environment variable overrides:
#   ANGELCLAW_TENANT_ID   Tenant identifier    (default: default)
#   ANGELCLAW_INSTALL_DIR Install directory     (default: C:\AngelClaw)
#   ANGELCLAW_BRANCH      Git branch           (default: main)
#   ANGELCLAW_FORCE       Force clean reinstall (set to "true")
# ============================================================================

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Configuration (override via environment variables)
# ---------------------------------------------------------------------------
$TenantId   = if ($env:ANGELCLAW_TENANT_ID)   { $env:ANGELCLAW_TENANT_ID }   else { "default" }
$InstallDir = if ($env:ANGELCLAW_INSTALL_DIR)  { $env:ANGELCLAW_INSTALL_DIR }  else { "C:\AngelClaw" }
$Branch     = if ($env:ANGELCLAW_BRANCH)       { $env:ANGELCLAW_BRANCH }       else { "main" }
$ForceClean = ($env:ANGELCLAW_FORCE -eq "true")

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
Write-Host "   V3.0.0 -- Dominion"                            -ForegroundColor Cyan
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

Write-Ok "Running as Administrator."
Write-Host "  Tenant ID    : $TenantId"
Write-Host "  Install dir  : $InstallDir"
Write-Host "  Branch       : $Branch"

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
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to install Git via winget. Install manually:"
        Write-Host "  https://git-scm.com/download/win"
        exit 1
    }
    Refresh-Path
    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if (-not $gitCmd) {
        # Try common install paths
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
            Write-Err "Git installed but cannot be found. Please close and reopen PowerShell, then re-run this script."
            exit 1
        }
    }
    Write-Ok "Git installed successfully."
} else {
    Write-Ok "Git found."
}

# ---------------------------------------------------------------------------
# Step 3: Check / Install Docker Desktop
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
        Write-Host "  Waiting for Docker to start (up to 90s)..." -ForegroundColor Gray
        $waited = 0
        while ($waited -lt 90) {
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
        $dcCmd = "compose"
    }
} catch {}

if (-not $dcCmd) {
    $dockerComposeCmd = Get-Command docker-compose -ErrorAction SilentlyContinue
    if ($dockerComposeCmd) {
        $composeVer = docker-compose --version 2>&1
        Write-Ok "docker-compose found: $composeVer"
        $dcCmd = "legacy"
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

if ($ForceClean -and (Test-Path $InstallDir)) {
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
# Step 6: Write environment config
# ---------------------------------------------------------------------------
Write-Step "Writing configuration..."

$configDir = Join-Path $InstallDir "ops\config"
if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
}

$configFile = Join-Path $configDir "angelclaw.env"
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$configContent = @"
# AngelClaw AGI Guardian -- generated by installer on $timestamp
ANGELCLAW_TENANT_ID=$TenantId
ANGELCLAW_CLOUD_URL=http://cloud:8500
ANGELCLAW_BIND_HOST=127.0.0.1
ANGELCLAW_BIND_PORT=8500
ANGELCLAW_AUTH_ENABLED=true
ANGELCLAW_SYNC_INTERVAL=60
LLM_ENABLED=false
LLM_MODEL=llama3
"@

Set-Content -Path $configFile -Value $configContent -Encoding UTF8
Write-Ok "Config written to $configFile"

# ---------------------------------------------------------------------------
# Step 7: Build and start full stack
# ---------------------------------------------------------------------------
Write-Step "Building and starting AngelClaw stack..."

$opsDir = Join-Path $InstallDir "ops"
Push-Location $opsDir
try {
    if ($dcCmd -eq "compose") {
        docker compose up -d --build
    } else {
        docker-compose up -d --build
    }
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose returned exit code $LASTEXITCODE"
    }
    Write-Ok "AngelClaw stack started (ANGELNODE + Cloud + Ollama)."
} catch {
    Write-Err "Failed to start containers: $_"
    Write-Host "  Try running manually:"
    Write-Host "    cd $opsDir"
    Write-Host "    docker compose up -d --build"
} finally {
    Pop-Location
}

# ---------------------------------------------------------------------------
# Step 8: Health check with retries
# ---------------------------------------------------------------------------
Write-Step "Verifying services..."

Write-Host "  Waiting for startup..." -ForegroundColor Gray
Start-Sleep -Seconds 10

# Check ANGELNODE
$nodeHealthy = $false
for ($attempt = 1; $attempt -le 3; $attempt++) {
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:8400/health" -TimeoutSec 5
        $nodeHealthy = $true
        break
    } catch {
        if ($attempt -lt 3) {
            Write-Host "  ANGELNODE retry $attempt/3..." -ForegroundColor Gray
            Start-Sleep -Seconds 5
        }
    }
}

if ($nodeHealthy) {
    Write-Ok "ANGELNODE is healthy (port 8400)"
} else {
    Write-Warn "ANGELNODE health check failed -- container may still be starting."
}

# Check Cloud API
$cloudHealthy = $false
for ($attempt = 1; $attempt -le 3; $attempt++) {
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:8500/health" -TimeoutSec 5
        $cloudHealthy = $true
        break
    } catch {
        if ($attempt -lt 3) {
            Write-Host "  Cloud API retry $attempt/3..." -ForegroundColor Gray
            Start-Sleep -Seconds 5
        }
    }
}

if ($cloudHealthy) {
    Write-Ok "Cloud API is healthy (port 8500)"
} else {
    Write-Warn "Cloud API health check failed -- container may still be starting."
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "   AngelClaw AGI Guardian -- Installed!"          -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Install dir  : $InstallDir"
Write-Host "  Config       : $configFile"
Write-Host "  Tenant ID    : $TenantId"
Write-Host ""
Write-Host "  Access:"
Write-Host "    Dashboard  : http://127.0.0.1:8500/ui"
Write-Host "    ANGELNODE  : http://127.0.0.1:8400"
Write-Host "    Cloud API  : http://127.0.0.1:8500"
Write-Host ""
Write-Host "  Default login: admin / fzMiSbDRGylsWrsaljMv7UxzrwdXCdTe" -ForegroundColor Yellow
Write-Host "  Change the password immediately after first login!" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Useful commands:"
Write-Host "    docker ps                                # check containers"
Write-Host "    docker logs angelclaw-angelnode-1 -f     # follow node logs"
Write-Host "    docker logs angelclaw-cloud-1 -f         # follow cloud logs"
Write-Host ""
Write-Host "  Multi-tenancy:"
Write-Host "    Each ANGELNODE uses a Tenant ID to isolate data."
Write-Host "    Set `$env:ANGELCLAW_TENANT_ID before re-running to add tenants."
Write-Host ""
Write-Host "  Uninstall:"
Write-Host "    & `"$InstallDir\ops\install\uninstall_angelclaw_windows.ps1`""
Write-Host ""
Write-Host "  AngelClaw V3.0.0 -- Dominion" -ForegroundColor Cyan
Write-Host "  Guardian angel, not gatekeeper." -ForegroundColor Cyan
Write-Host ""
