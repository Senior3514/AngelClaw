# ============================================================================
# AngelClaw AGI Guardian -- Windows ANGELNODE Installer (V2.0.0) [LEGACY]
#
# DEPRECATED: This script redirects to install_angelclaw_windows.ps1
# Use install_angelclaw_windows.ps1 directly for new installations.
# ============================================================================

param(
    [string]$CloudUrl   = "http://your-cloud-server:8500",
    [string]$TenantId   = "default",
    [string]$InstallDir = "C:\AngelClaw",
    [string]$Branch     = "main"
)

Write-Host ""
Write-Host "[AngelClaw] NOTE: install_angelnode_windows.ps1 is deprecated." -ForegroundColor Yellow
Write-Host "[AngelClaw] Redirecting to install_angelclaw_windows.ps1..." -ForegroundColor Yellow
Write-Host ""

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$newScript = Join-Path $scriptDir "install_angelclaw_windows.ps1"

if (Test-Path $newScript) {
    & $newScript -CloudUrl $CloudUrl -TenantId $TenantId -InstallDir $InstallDir -Branch $Branch
} else {
    Write-Host "[X] Could not find install_angelclaw_windows.ps1 at $newScript" -ForegroundColor Red
    Write-Host "  Download from: https://github.com/Senior3514/AngelClaw"
    exit 1
}
