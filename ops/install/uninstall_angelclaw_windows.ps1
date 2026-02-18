# ============================================================================
# AngelClaw AGI Guardian — Windows Uninstaller (V2.0.0)
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

function Log($msg)  { Write-Host "[AngelClaw] $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "[OK] $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Err($msg)  { Write-Host "[X] $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "+================================================+" -ForegroundColor Red
Write-Host "|   AngelClaw AGI Guardian - Windows Uninstaller  |" -ForegroundColor Red
Write-Host "+================================================+" -ForegroundColor Red
Write-Host ""

# ---------------------------------------------------------------------------
# Step 1: Check Docker
# ---------------------------------------------------------------------------
$dockerOk = $false
try {
    docker info 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { $dockerOk = $true }
} catch {
    $dockerOk = $false
}

if (-not $dockerOk) {
    Warn "Docker Desktop is not running. Start it first for full cleanup."
    Warn "Continuing with file removal only..."
}

# ---------------------------------------------------------------------------
# Step 2: Stop and remove containers
# ---------------------------------------------------------------------------
if ($dockerOk -and (Test-Path "$InstallDir\ops")) {
    Log "Stopping AngelClaw containers..."
    Push-Location "$InstallDir\ops"

    try {
        docker compose down --remove-orphans --volumes 2>$null
        if ($LASTEXITCODE -ne 0) {
            docker-compose down --remove-orphans --volumes 2>$null
        }
        Ok "Containers stopped and removed."
    } catch {
        Warn "Could not stop containers: $_"
    }

    Pop-Location
} else {
    Warn "Install directory not found or Docker not running - skipping container teardown."
}

# ---------------------------------------------------------------------------
# Step 3: Remove Docker images
# ---------------------------------------------------------------------------
if ($dockerOk) {
    Log "Removing AngelClaw Docker images..."

    $images = docker images --filter "reference=*angelclaw*" --filter "reference=*angelnode*" --filter "reference=*angelgrid*" -q 2>$null
    if ($images) {
        $images | ForEach-Object { docker rmi -f $_ 2>$null }
        Ok "Docker images removed."
    } else {
        Warn "No AngelClaw images found."
    }

    $opsImages = docker images --filter "reference=ops-*" -q 2>$null
    if ($opsImages) {
        $opsImages | ForEach-Object { docker rmi -f $_ 2>$null }
        Ok "Compose-built images removed."
    }

    # ---------------------------------------------------------------------------
    # Step 4: Remove Docker volumes
    # ---------------------------------------------------------------------------
    Log "Removing AngelClaw Docker volumes..."

    $volumes = docker volume ls -q --filter "name=angelclaw" --filter "name=angelgrid" --filter "name=ops_" 2>$null
    if ($volumes) {
        $volumes | ForEach-Object { docker volume rm -f $_ 2>$null }
        Ok "Docker volumes removed."
    } else {
        Warn "No AngelClaw volumes found."
    }

    # ---------------------------------------------------------------------------
    # Step 5: Prune dangling resources
    # ---------------------------------------------------------------------------
    Log "Pruning dangling Docker resources..."
    docker system prune -f 2>$null | Out-Null
    Ok "Docker cleanup complete."
}

# ---------------------------------------------------------------------------
# Step 6: Remove install directory
# ---------------------------------------------------------------------------
if ($KeepData) {
    Warn "KeepData flag set - keeping install directory at $InstallDir"
} else {
    if (Test-Path $InstallDir) {
        Log "Removing install directory: $InstallDir"
        Remove-Item -Recurse -Force $InstallDir
        Ok "Install directory removed."
    } else {
        Warn "Install directory not found at $InstallDir - nothing to remove."
    }
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "+================================================+" -ForegroundColor Green
Write-Host "|   AngelClaw has been uninstalled.               |" -ForegroundColor Green
Write-Host "+================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  What was removed:"
Write-Host "    - Docker containers, images, and volumes"
if (-not $KeepData) {
    Write-Host "    - Install directory ($InstallDir)"
}
Write-Host ""
Write-Host "  Docker Desktop was NOT removed."
Write-Host "  To reinstall, run:"
Write-Host "    git clone https://github.com/Senior3514/AngelClaw.git C:\AngelClaw"
Write-Host "    C:\AngelClaw\ops\install\install_angelclaw_windows.ps1 -CloudUrl `"http://YOUR-VPS-IP:8500`""
Write-Host ""
