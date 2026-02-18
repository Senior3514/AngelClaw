#!/usr/bin/env bash
# ============================================================================
# AngelClaw AGI Guardian -- Linux Uninstaller (V2.1.0)
#
# Stops all AngelClaw containers, removes systemd service, Docker images,
# volumes, and optionally deletes the install directory.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/uninstall_angelclaw_linux.sh | bash
#
# Or download and run manually:
#   chmod +x uninstall_angelclaw_linux.sh
#   ./uninstall_angelclaw_linux.sh
#
# Optional environment variables:
#   ANGELCLAW_DIR         Install directory    (default: /root/AngelClaw)
#   ANGELCLAW_KEEP_DATA   Keep install dir     (default: false)
# ============================================================================

set -euo pipefail

INSTALL_DIR="${ANGELCLAW_DIR:-/root/AngelClaw}"
KEEP_DATA="${ANGELCLAW_KEEP_DATA:-false}"

TOTAL_STEPS=6
STEP=0

# Colors
G='\033[92m' Y='\033[93m' R='\033[91m' C='\033[96m' B='\033[1m' N='\033[0m'

step() { STEP=$((STEP+1)); echo -e "${C}[$STEP/$TOTAL_STEPS]${N} $1"; }
ok()   { echo -e "  ${G}[OK]${N} $1"; }
warn() { echo -e "  ${Y}[!]${N} $1"; }
err()  { echo -e "  ${R}[X]${N} $1"; }

echo ""
echo -e "${B}${R}================================================${N}"
echo -e "${B}${R}  AngelClaw AGI Guardian -- Linux Uninstaller${N}"
echo -e "${B}${R}================================================${N}"
echo ""

# Must be root
if [ "$(id -u)" -ne 0 ]; then
  err "This uninstaller must be run as root (or with sudo)."
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Stop and remove systemd service
# ---------------------------------------------------------------------------
step "Removing systemd service..."

if [ -f /etc/systemd/system/angelclaw.service ]; then
  systemctl stop angelclaw.service 2>/dev/null || true
  systemctl disable angelclaw.service 2>/dev/null || true
  rm -f /etc/systemd/system/angelclaw.service
  systemctl daemon-reload
  ok "systemd service removed (angelclaw.service)."
else
  warn "No systemd service found -- skipping."
fi

# Also clean up legacy angelgrid service if present
if [ -f /etc/systemd/system/angelgrid.service ]; then
  systemctl stop angelgrid.service 2>/dev/null || true
  systemctl disable angelgrid.service 2>/dev/null || true
  rm -f /etc/systemd/system/angelgrid.service
  rm -f /etc/systemd/system/angelgrid-watchdog.service
  rm -f /etc/systemd/system/angelgrid-watchdog.timer
  systemctl daemon-reload
  ok "Legacy angelgrid systemd services removed."
fi

# ---------------------------------------------------------------------------
# Step 2: Stop and remove containers
# ---------------------------------------------------------------------------
step "Stopping containers..."

if [ -d "$INSTALL_DIR/ops" ]; then
  cd "$INSTALL_DIR/ops"
  DC_CMD=""
  if docker compose version &>/dev/null 2>&1; then
    DC_CMD="docker compose"
  elif command -v docker-compose &>/dev/null; then
    DC_CMD="docker-compose"
  fi

  if [ -n "$DC_CMD" ]; then
    $DC_CMD down --remove-orphans --volumes 2>/dev/null || true
    ok "Containers stopped and removed."
  else
    warn "docker compose not found -- attempting manual container removal."
  fi
else
  warn "Install directory not found at $INSTALL_DIR -- skipping container teardown."
fi

# ---------------------------------------------------------------------------
# Step 3: Remove Docker images
# ---------------------------------------------------------------------------
step "Removing Docker images..."

IMAGES=$(docker images --filter "reference=*angelclaw*" --filter "reference=*angelnode*" --filter "reference=*angelgrid*" -q 2>/dev/null || true)
if [ -n "$IMAGES" ]; then
  docker rmi -f $IMAGES 2>/dev/null || true
  ok "Docker images removed."
else
  warn "No AngelClaw images found."
fi

# Also remove ops-prefixed images from docker compose builds
OPS_IMAGES=$(docker images --filter "reference=ops-*" -q 2>/dev/null || true)
if [ -n "$OPS_IMAGES" ]; then
  docker rmi -f $OPS_IMAGES 2>/dev/null || true
  ok "Compose-built images removed."
fi

# ---------------------------------------------------------------------------
# Step 4: Remove Docker volumes
# ---------------------------------------------------------------------------
step "Removing Docker volumes..."

VOLUMES=$(docker volume ls -q --filter "name=angelclaw" --filter "name=angelgrid" --filter "name=ops_" 2>/dev/null || true)
if [ -n "$VOLUMES" ]; then
  docker volume rm -f $VOLUMES 2>/dev/null || true
  ok "Docker volumes removed."
else
  warn "No AngelClaw volumes found."
fi

# ---------------------------------------------------------------------------
# Step 5: Remove install directory
# ---------------------------------------------------------------------------
step "Removing install directory..."

if [ "$KEEP_DATA" = "true" ]; then
  warn "ANGELCLAW_KEEP_DATA=true -- keeping install directory at $INSTALL_DIR"
else
  if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    ok "Install directory removed: $INSTALL_DIR"
  else
    warn "Install directory not found at $INSTALL_DIR -- nothing to remove."
  fi
fi

# ---------------------------------------------------------------------------
# Step 6: Prune dangling resources
# ---------------------------------------------------------------------------
step "Cleaning up Docker resources..."

docker system prune -f --filter "label=com.docker.compose.project=ops" 2>/dev/null || true
ok "Docker cleanup complete."

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${B}${G}================================================${N}"
echo -e "${B}${G}  AngelClaw has been uninstalled.${N}"
echo -e "${B}${G}================================================${N}"
echo ""
echo "  What was removed:"
echo "    - systemd service (angelclaw.service)"
echo "    - Docker containers, images, and volumes"
if [ "$KEEP_DATA" != "true" ]; then
  echo "    - Install directory ($INSTALL_DIR)"
fi
echo ""
echo "  Docker itself was NOT removed."
echo ""
echo "  To reinstall:"
echo "    curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash"
echo ""
