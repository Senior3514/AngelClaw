#!/usr/bin/env bash
# ============================================================================
# AngelClaw AGI Guardian -- macOS Uninstaller (V10.0.0)
#
# Stops all AngelClaw containers, removes Docker images, volumes,
# and optionally deletes the install directory.
#
# ONE-LINE UNINSTALL:
#   curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/uninstall_angelclaw_macos.sh | bash
#
# Or download and run manually:
#   chmod +x uninstall_angelclaw_macos.sh
#   ./uninstall_angelclaw_macos.sh
#
# Optional environment variables:
#   ANGELCLAW_DIR         Install directory    (default: ~/AngelClaw)
#   ANGELCLAW_KEEP_DATA   Keep install dir     (default: false)
# ============================================================================

set -euo pipefail

INSTALL_DIR="${ANGELCLAW_DIR:-$HOME/AngelClaw}"
KEEP_DATA="${ANGELCLAW_KEEP_DATA:-false}"

TOTAL_STEPS=5
STEP=0

# Colors
G='\033[92m' Y='\033[93m' R='\033[91m' C='\033[96m' B='\033[1m' N='\033[0m'

step() { STEP=$((STEP+1)); echo -e "${C}[$STEP/$TOTAL_STEPS]${N} $1"; }
ok()   { echo -e "  ${G}[OK]${N} $1"; }
warn() { echo -e "  ${Y}[!]${N} $1"; }
err()  { echo -e "  ${R}[X]${N} $1"; }

echo ""
echo -e "${B}${R}================================================${N}"
echo -e "${B}${R}  AngelClaw AGI Guardian -- macOS Uninstaller${N}"
echo -e "${B}${R}  V10.0.0 -- Titan Grid${N}"
echo -e "${B}${R}================================================${N}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Check Docker is running
# ---------------------------------------------------------------------------
step "Checking Docker..."

DOCKER_OK=false
if command -v docker &>/dev/null; then
  if docker info &>/dev/null 2>&1; then
    DOCKER_OK=true
    ok "Docker Desktop is running."
  else
    warn "Docker Desktop is not running. Continuing with file removal only..."
  fi
else
  warn "Docker not found -- skipping container cleanup."
fi

# ---------------------------------------------------------------------------
# Step 2: Stop and remove containers
# ---------------------------------------------------------------------------
step "Stopping containers..."

if [ -d "$INSTALL_DIR/ops" ] && [ "$DOCKER_OK" = true ]; then
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
  fi
else
  warn "Install directory not found or Docker not running -- skipping container teardown."
fi

# ---------------------------------------------------------------------------
# Step 3: Remove Docker images and volumes
# ---------------------------------------------------------------------------
step "Removing Docker images and volumes..."

if [ "$DOCKER_OK" = true ]; then
  IMAGES=$(docker images --filter "reference=*angelclaw*" --filter "reference=*angelnode*" --filter "reference=*angelgrid*" -q 2>/dev/null || true)
  if [ -n "$IMAGES" ]; then
    docker rmi -f $IMAGES 2>/dev/null || true
    ok "Docker images removed."
  else
    warn "No AngelClaw images found."
  fi

  OPS_IMAGES=$(docker images --filter "reference=ops-*" -q 2>/dev/null || true)
  if [ -n "$OPS_IMAGES" ]; then
    docker rmi -f $OPS_IMAGES 2>/dev/null || true
    ok "Compose-built images removed."
  fi

  VOLUMES=$(docker volume ls -q --filter "name=angelclaw" --filter "name=angelgrid" --filter "name=ops_" 2>/dev/null || true)
  if [ -n "$VOLUMES" ]; then
    docker volume rm -f $VOLUMES 2>/dev/null || true
    ok "Docker volumes removed."
  else
    warn "No AngelClaw volumes found."
  fi

  docker system prune -f --filter "label=com.docker.compose.project=ops" 2>/dev/null || true
  ok "Docker cleanup complete."
else
  warn "Docker not running -- skipping image/volume removal."
fi

# ---------------------------------------------------------------------------
# Step 4: Remove install directory
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
# Step 5: Final cleanup
# ---------------------------------------------------------------------------
step "Finalizing..."

ok "Uninstall complete."

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${B}${G}================================================${N}"
echo -e "${B}${G}  AngelClaw has been uninstalled.${N}"
echo -e "${B}${G}================================================${N}"
echo ""
echo "  What was removed:"
echo "    - Docker containers, images, and volumes"
if [ "$KEEP_DATA" != "true" ]; then
  echo "    - Install directory ($INSTALL_DIR)"
fi
echo ""
echo "  Docker Desktop was NOT removed."
echo ""
echo "  To reinstall:"
echo "    curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_macos.sh | bash"
echo ""
