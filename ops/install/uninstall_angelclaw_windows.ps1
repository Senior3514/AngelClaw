# ============================================================================
# AngelClaw AGI Guardian -- Windows Uninstaller (V10.0.0)
#
# Stops ANGELNODE, removes Scheduled Task, and deletes the install directory.
#
# Usage (PowerShell as Administrator):
#   & "C:\AngelClaw\ops\install\uninstall_angelclaw_windows.ps1"
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
$TotalSteps = 4
$script:CurrentStep = 0

function Write-Step {
    param([string]$msg)
    $script:CurrentStep++
    Write-Host ""
    Write-Host "[$script:CurrentStep/$TotalSteps] $msg" -ForegroundColor Cyan
}
function Write-Ok   { param([string]$msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "  [!]  $msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "================================================" -ForegroundColor Red
Write-Host "   AngelClaw AGI Guardian -- Windows Uninstaller" -ForegroundColor Red
Write-Host "   V10.0.0 -- Seraph"                                   -ForegroundColor Red
Write-Host "================================================" -ForegroundColor Red

# ---------------------------------------------------------------------------
# Step 1: Stop ANGELNODE process
# ---------------------------------------------------------------------------
Write-Step "Stopping ANGELNODE..."

$procs = Get-Process -Name "uvicorn" -ErrorAction SilentlyContinue
if ($procs) {
    $procs | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Ok "ANGELNODE process stopped."
} else {
    Write-Warn "No ANGELNODE process found -- already stopped."
}

# ---------------------------------------------------------------------------
# Step 2: Remove Scheduled Task
# ---------------------------------------------------------------------------
Write-Step "Removing auto-start task..."

$taskName = "AngelClaw-ANGELNODE"
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($task) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Ok "Scheduled task removed ($taskName)."
} else {
    Write-Warn "No scheduled task found -- skipping."
}

# ---------------------------------------------------------------------------
# Step 3: Remove install directory
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
# Step 4: Verify
# ---------------------------------------------------------------------------
Write-Step "Verifying cleanup..."

$stillRunning = Get-Process -Name "uvicorn" -ErrorAction SilentlyContinue
if ($stillRunning) {
    Write-Warn "uvicorn process still running. You may need to restart."
} else {
    Write-Ok "All clean."
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
Write-Host "    - ANGELNODE process"
Write-Host "    - Auto-start scheduled task"
if (-not $KeepData) {
    Write-Host "    - Install directory ($InstallDir)"
}
Write-Host ""
Write-Host "  Python was NOT removed."
Write-Host ""
Write-Host "  To reinstall (PowerShell as Admin):"
Write-Host "    irm https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.ps1 | iex"
Write-Host ""
