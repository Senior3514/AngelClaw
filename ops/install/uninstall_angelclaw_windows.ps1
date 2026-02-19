# ============================================================================
# AngelClaw AGI Guardian -- Windows Uninstaller (V3.0.0)
#
# Stops ANGELNODE container, removes Docker images, volumes,
# and optionally deletes the install directory.
#
# Usage (PowerShell as Administrator):
#   C:\AngelClaw\ops\install\uninstall_angelclaw_windows.ps1
#
# Parameters:
#   -InstallDir   Install directory    (default: C:\AngelClaw)
#   -KeepData     Keep install dir     (default: $false)
# ============================================================================

param(
    [string]$InstallDir = "C:\AngelClaw",
    [switch]$KeepData = $false
)

$ErrorActionPreference = "Continue"
$TotalSteps = 6
$script:CurrentStep = 0

function Write-Step {
    param([string]$msg)
    $script:CurrentStep++
    Write-Host "[$script:CurrentStep/$TotalSteps] $msg" -ForegroundColor Cyan
}
function Write-Ok   { param([string]$msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "  [!]  $msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$msg) Write-Host "  [X]  $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "================================================" -ForegroundColor Red
Write-Host "   AngelClaw AGI Guardian -- Windows Uninstaller" -ForegroundColor Red
Write-Host "   V3.0.0 -- Dominion"                              -ForegroundColor Red
Write-Host "================================================" -ForegroundColor Red
Write-Host ""

# ---------------------------------------------------------------------------
# Step 1: Check Docker
# ---------------------------------------------------------------------------
Write-Step "Checking Docker..."

$dockerOk = $false
try {
    $null = docker info 2>&1
    if ($LASTEXITCODE -eq 0) { $dockerOk = $true }
} catch {}

if (-not $dockerOk) {
    Write-Warn "Docker Desktop is not running. Continuing with file removal only..."
} else {
    Write-Ok "Docker is running."
}

# ---------------------------------------------------------------------------
# Step 2: Stop and remove containers
# ---------------------------------------------------------------------------
Write-Step "Stopping containers..."

if ($dockerOk -and (Test-Path "$InstallDir\ops")) {
    Push-Location "$InstallDir\ops"
    try {
        docker compose down --remove-orphans --volumes 2>$null
        if ($LASTEXITCODE -ne 0) {
            docker-compose down --remove-orphans --volumes 2>$null
        }
        Write-Ok "Containers stopped and removed."
    } catch {
        Write-Warn "Could not stop containers: $_"
    } finally {
        Pop-Location
    }
} else {
    Write-Warn "Install directory not found or Docker not running -- skipping container teardown."
}

# ---------------------------------------------------------------------------
# Step 3: Remove Docker images
# ---------------------------------------------------------------------------
Write-Step "Removing Docker images..."

if ($dockerOk) {
    $images = docker images --filter "reference=*angelclaw*" --filter "reference=*angelnode*" --filter "reference=*angelgrid*" -q 2>$null
    if ($images) {
        $images | ForEach-Object { docker rmi -f $_ 2>$null }
        Write-Ok "Docker images removed."
    } else {
        Write-Warn "No AngelClaw images found."
    }

    $opsImages = docker images --filter "reference=ops-*" -q 2>$null
    if ($opsImages) {
        $opsImages | ForEach-Object { docker rmi -f $_ 2>$null }
        Write-Ok "Compose-built images removed."
    }
} else {
    Write-Warn "Docker not running -- skipping image removal."
}

# ---------------------------------------------------------------------------
# Step 4: Remove Docker volumes
# ---------------------------------------------------------------------------
Write-Step "Removing Docker volumes..."

if ($dockerOk) {
    $volumes = docker volume ls -q --filter "name=angelclaw" --filter "name=angelgrid" --filter "name=ops_" 2>$null
    if ($volumes) {
        $volumes | ForEach-Object { docker volume rm -f $_ 2>$null }
        Write-Ok "Docker volumes removed."
    } else {
        Write-Warn "No AngelClaw volumes found."
    }
} else {
    Write-Warn "Docker not running -- skipping volume removal."
}

# ---------------------------------------------------------------------------
# Step 5: Prune dangling resources
# ---------------------------------------------------------------------------
Write-Step "Cleaning up Docker resources..."

if ($dockerOk) {
    docker system prune -f 2>$null | Out-Null
    Write-Ok "Docker cleanup complete."
} else {
    Write-Warn "Docker not running -- skipping cleanup."
}

# ---------------------------------------------------------------------------
# Step 6: Remove install directory
# ---------------------------------------------------------------------------
Write-Step "Removing install directory..."

if ($KeepData) {
    Write-Warn "KeepData flag set -- keeping install directory at $InstallDir"
} else {
    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
        Write-Ok "Install directory removed: $InstallDir"
    } else {
        Write-Warn "Install directory not found at $InstallDir -- nothing to remove."
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "   AngelClaw has been uninstalled."               -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  What was removed:"
Write-Host "    - Docker containers, images, and volumes"
if (-not $KeepData) {
    Write-Host "    - Install directory ($InstallDir)"
}
Write-Host ""
Write-Host "  Docker Desktop was NOT removed."
Write-Host ""
Write-Host "  To reinstall (PowerShell as Admin):"
Write-Host "    irm https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.ps1 | iex"
Write-Host ""
