#!/usr/bin/env bash
# ============================================================================
# AngelClaw AGI Guardian — macOS Installer (V1.2.0)
#
# Installs the full AngelClaw stack (ANGELNODE + Cloud + Ollama) on macOS
# using Docker Desktop + Docker Compose.
#
# One-command install:
#   curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_macos.sh | bash
#
# Or download and run manually:
#   chmod +x install_angelclaw_macos.sh
#   ./install_angelclaw_macos.sh
#
# Optional environment variables:
#   ANGELCLAW_REPO        Git repo URL       (default: https://github.com/Senior3514/AngelClaw.git)
#   ANGELCLAW_BRANCH      Branch to checkout  (default: main)
#   ANGELCLAW_DIR         Install directory    (default: ~/AngelClaw)
#   ANGELCLAW_TENANT_ID   Tenant identifier    (default: default)
#   ANGELCLAW_CLOUD_URL   Cloud URL for agents (default: http://cloud:8500)
#   LLM_ENABLED           Enable LLM proxy     (default: false)
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REPO="${ANGELCLAW_REPO:-https://github.com/Senior3514/AngelClaw.git}"
BRANCH="${ANGELCLAW_BRANCH:-main}"
INSTALL_DIR="${ANGELCLAW_DIR:-$HOME/AngelClaw}"
TENANT_ID="${ANGELCLAW_TENANT_ID:-default}"
CLOUD_URL="${ANGELCLAW_CLOUD_URL:-http://cloud:8500}"
LLM="${LLM_ENABLED:-false}"

# Colors
G='\033[92m' Y='\033[93m' R='\033[91m' C='\033[96m' B='\033[1m' N='\033[0m'

log()  { echo -e "${C}[AngelClaw]${N} $1"; }
ok()   { echo -e "${G}[OK]${N} $1"; }
warn() { echo -e "${Y}[!]${N} $1"; }
err()  { echo -e "${R}[X]${N} $1"; }

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo ""
echo -e "${B}${C}+================================================+${N}"
echo -e "${B}${C}|   AngelClaw AGI Guardian — macOS Installer      |${N}"
echo -e "${B}${C}|   V1.1.0 — Guardian Angel, Not Gatekeeper       |${N}"
echo -e "${B}${C}+================================================+${N}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Check Homebrew (install if missing)
# ---------------------------------------------------------------------------
log "Checking Homebrew..."

if command -v brew &>/dev/null; then
  ok "Homebrew found."
else
  warn "Homebrew is not installed."
  echo ""
  echo "  Homebrew is the recommended package manager for macOS."
  read -rp "  Install Homebrew now? [Y/n] " INSTALL_BREW
  if [[ ! "$INSTALL_BREW" =~ ^[Nn]$ ]]; then
    log "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # Add Homebrew to PATH for Apple Silicon Macs
    if [ -f /opt/homebrew/bin/brew ]; then
      eval "$(/opt/homebrew/bin/brew shellenv)"
    fi
    ok "Homebrew installed."
  else
    err "Homebrew is required for automated Docker installation."
    echo "  You can install Docker Desktop manually from:"
    echo "  https://docs.docker.com/desktop/install/mac-install/"
    echo ""
    echo "  Then re-run this script."
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# Step 2: Check Docker Desktop
# ---------------------------------------------------------------------------
log "Checking Docker..."

if command -v docker &>/dev/null; then
  DOCKER_VER=$(docker --version 2>/dev/null || echo "unknown")
  ok "Docker found: $DOCKER_VER"
else
  warn "Docker is not installed."
  echo ""
  read -rp "  Install Docker Desktop via Homebrew? [Y/n] " INSTALL_DOCKER
  if [[ ! "$INSTALL_DOCKER" =~ ^[Nn]$ ]]; then
    log "Installing Docker Desktop..."
    brew install --cask docker
    echo ""
    echo -e "${Y}  Docker Desktop has been installed but needs to be started.${N}"
    echo "  Please open Docker Desktop from your Applications folder,"
    echo "  wait for it to finish starting, then re-run this script."
    echo ""
    open -a Docker 2>/dev/null || true
    exit 0
  else
    err "Docker is required. Install Docker Desktop and re-run this script."
    echo "  https://docs.docker.com/desktop/install/mac-install/"
    exit 1
  fi
fi

# Verify Docker daemon is running
if ! docker info &>/dev/null 2>&1; then
  err "Docker daemon is not running."
  echo "  Please start Docker Desktop and wait for it to finish loading."
  echo "  Then re-run this script."
  open -a Docker 2>/dev/null || true
  exit 1
fi
ok "Docker daemon is running."

# ---------------------------------------------------------------------------
# Step 3: Check docker compose
# ---------------------------------------------------------------------------
log "Checking docker compose..."

if docker compose version &>/dev/null 2>&1; then
  DC_VER=$(docker compose version 2>/dev/null || echo "unknown")
  ok "docker compose found: $DC_VER"
  DC_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
  DC_VER=$(docker-compose --version 2>/dev/null || echo "unknown")
  ok "docker-compose found: $DC_VER"
  DC_CMD="docker-compose"
else
  err "docker-compose is not available."
  echo "  Docker Desktop should include 'docker compose'. Please update Docker Desktop."
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 4: Check git
# ---------------------------------------------------------------------------
log "Checking git..."

if ! command -v git &>/dev/null; then
  log "Installing git via Homebrew..."
  brew install git
  ok "git installed."
else
  ok "git found."
fi

# ---------------------------------------------------------------------------
# Step 5: Clone or update repo
# ---------------------------------------------------------------------------
log "Setting up AngelClaw at $INSTALL_DIR..."

if [ -d "$INSTALL_DIR/.git" ]; then
  log "Existing installation found — pulling latest..."
  cd "$INSTALL_DIR"
  git fetch origin
  git checkout "$BRANCH"
  git pull origin "$BRANCH"
  ok "Repository updated."
else
  log "Cloning repository..."
  git clone --branch "$BRANCH" "$REPO" "$INSTALL_DIR"
  ok "Repository cloned."
fi

cd "$INSTALL_DIR"

# ---------------------------------------------------------------------------
# Step 6: Write config
# ---------------------------------------------------------------------------
log "Writing configuration..."

CONFIG_FILE="$INSTALL_DIR/ops/config/angelclaw.env"
mkdir -p "$INSTALL_DIR/ops/config"

cat > "$CONFIG_FILE" <<ENVEOF
# AngelClaw AGI Guardian environment — generated by installer on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
ANGELCLAW_CLOUD_URL=${CLOUD_URL}
ANGELCLAW_TENANT_ID=${TENANT_ID}
ANGELCLAW_BIND_HOST=127.0.0.1
ANGELCLAW_BIND_PORT=8500
ANGELCLAW_AUTH_ENABLED=true
ANGELCLAW_SYNC_INTERVAL=60
LLM_ENABLED=${LLM}
LLM_MODEL=llama3
ENVEOF

ok "Config written to $CONFIG_FILE"

# ---------------------------------------------------------------------------
# Step 7: Build and start containers
# ---------------------------------------------------------------------------
log "Building and starting AngelClaw stack..."

cd "$INSTALL_DIR/ops"
$DC_CMD up -d --build

ok "Containers started."

# ---------------------------------------------------------------------------
# Step 8: Health check
# ---------------------------------------------------------------------------
log "Waiting for services to become healthy..."
sleep 10

HEALTHY=true
if curl -sf --max-time 5 http://127.0.0.1:8400/health >/dev/null 2>&1; then
  ok "ANGELNODE is healthy (port 8400)"
else
  warn "ANGELNODE health check failed — it may still be starting."
  HEALTHY=false
fi

if curl -sf --max-time 5 http://127.0.0.1:8500/health >/dev/null 2>&1; then
  ok "Cloud API is healthy (port 8500)"
else
  warn "Cloud API health check failed — it may still be starting."
  HEALTHY=false
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${B}${G}+================================================+${N}"
echo -e "${B}${G}|   AngelClaw AGI Guardian installed on macOS!    |${N}"
echo -e "${B}${G}+================================================+${N}"
echo ""
echo "  Install dir  : $INSTALL_DIR"
echo "  Config       : $CONFIG_FILE"
echo "  Tenant ID    : $TENANT_ID"
echo ""
echo "  Access:"
echo "    Dashboard  : http://127.0.0.1:8500/ui"
echo "    ANGELNODE  : http://127.0.0.1:8400"
echo "    Cloud API  : http://127.0.0.1:8500"
echo ""
echo "  Chat with AngelClaw:"
echo "    curl -X POST http://127.0.0.1:8500/api/v1/angelclaw/chat \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"tenantId\":\"default\",\"prompt\":\"Scan the system\"}'"
echo ""
echo "  Useful commands:"
echo "    docker ps                              # check containers"
echo "    docker logs angelclaw-angelnode-1 -f   # follow node logs"
echo "    docker logs angelclaw-cloud-1 -f       # follow cloud logs"
echo "    $INSTALL_DIR/ops/cli/angelclawctl status   # CLI status"
echo ""

if [ "$LLM" = "true" ]; then
  echo "  LLM proxy is enabled. Pull a model:"
  echo "    cd $INSTALL_DIR/ops && $DC_CMD exec ollama ollama pull llama3"
  echo ""
fi

echo -e "  ${C}AngelClaw AGI Guardian — guardian angel, not gatekeeper.${N}"
echo ""
