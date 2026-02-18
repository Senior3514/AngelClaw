#!/usr/bin/env bash
# ============================================================================
# AngelClaw AGI Guardian — Linux Uninstaller (V2.0.0)
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

# Colors
G='\033[92m' Y='\033[93m' R='\033[91m' C='\033[96m' B='\033[1m' N='\033[0m'

log()  { echo -e "${C}[AngelClaw]${N} $1"; }
ok()   { echo -e "${G}[OK]${N} $1"; }
warn() { echo -e "${Y}[!]${N} $1"; }
err()  { echo -e "${R}[X]${N} $1"; }

echo ""
echo -e "${B}${R}+================================================+${N}"
echo -e "${B}${R}|   AngelClaw AGI Guardian — Linux Uninstaller    |${N}"
echo -e "${B}${R}+================================================+${N}"
echo ""

# Must be root
if [ "$(id -u)" -ne 0 ]; then
  err "This uninstaller must be run as root (or with sudo)."
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Stop and remove systemd service
# ---------------------------------------------------------------------------
log "Removing systemd service..."

if [ -f /etc/systemd/system/angelclaw.service ]; then
  systemctl stop angelclaw.service 2>/dev/null || true
  systemctl disable angelclaw.service 2>/dev/null || true
  rm -f /etc/systemd/system/angelclaw.service
  systemctl daemon-reload
  ok "systemd service removed."
else
  warn "No systemd service found — skipping."
fi

# ---------------------------------------------------------------------------
# Step 2: Stop and remove containers
# ---------------------------------------------------------------------------
log "Stopping AngelClaw containers..."

if [ -d "$INSTALL_DIR/ops" ]; then
  cd "$INSTALL_DIR/ops"
  if docker compose version &>/dev/null 2>&1; then
    DC_CMD="docker compose"
  elif command -v docker-compose &>/dev/null; then
    DC_CMD="docker-compose"
  else
    DC_CMD=""
  fi

  if [ -n "$DC_CMD" ]; then
    $DC_CMD down --remove-orphans --volumes 2>/dev/null || true
    ok "Containers stopped and removed."
  else
    warn "docker-compose not found — attempting manual container removal."
  fi
else
  warn "Install directory not found at $INSTALL_DIR — skipping container teardown."
fi

# ---------------------------------------------------------------------------
# Step 3: Remove Docker images
# ---------------------------------------------------------------------------
log "Removing AngelClaw Docker images..."

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
log "Removing AngelClaw Docker volumes..."

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
if [ "$KEEP_DATA" = "true" ]; then
  warn "ANGELCLAW_KEEP_DATA=true — keeping install directory at $INSTALL_DIR"
else
  if [ -d "$INSTALL_DIR" ]; then
    log "Removing install directory: $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
    ok "Install directory removed."
  else
    warn "Install directory not found at $INSTALL_DIR — nothing to remove."
  fi
fi

# ---------------------------------------------------------------------------
# Step 6: Prune dangling resources
# ---------------------------------------------------------------------------
log "Pruning dangling Docker resources..."
docker system prune -f --filter "label=com.docker.compose.project=ops" 2>/dev/null || true
ok "Cleanup complete."

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${B}${G}+================================================+${N}"
echo -e "${B}${G}|   AngelClaw has been uninstalled.                |${N}"
echo -e "${B}${G}+================================================+${N}"
echo ""
echo "  What was removed:"
echo "    - systemd service (angelclaw.service)"
echo "    - Docker containers, images, and volumes"
if [ "$KEEP_DATA" != "true" ]; then
  echo "    - Install directory ($INSTALL_DIR)"
fi
echo ""
echo "  Docker itself was NOT removed."
echo "  To reinstall, run:"
echo "    curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash"
echo ""
