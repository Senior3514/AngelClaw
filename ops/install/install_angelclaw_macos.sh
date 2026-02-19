#!/usr/bin/env bash
# ============================================================================
# AngelClaw AGI Guardian -- macOS Installer (V3.0.0)
#
# Installs the full AngelClaw stack (ANGELNODE + Cloud + Ollama) on macOS
# using Docker Desktop + Docker Compose. Auto-installs Homebrew and Docker
# Desktop if missing.
#
# ONE-LINE INSTALL:
#   curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_macos.sh | bash
#
# CUSTOM TENANT:
#   ANGELCLAW_TENANT_ID="acme-corp" curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_macos.sh | bash
#
# Optional environment variables:
#   ANGELCLAW_REPO        Git repo URL       (default: https://github.com/Senior3514/AngelClaw.git)
#   ANGELCLAW_BRANCH      Branch to checkout  (default: main)
#   ANGELCLAW_DIR         Install directory    (default: ~/AngelClaw)
#   ANGELCLAW_TENANT_ID   Tenant identifier    (default: default)
#   ANGELCLAW_CLOUD_URL   Cloud URL for agents (default: http://cloud:8500)
#   LLM_ENABLED           Enable LLM proxy     (default: false)
#   ANGELCLAW_FORCE       Force clean reinstall (default: false)
#   GH_USER               GitHub username       (prompted if not set)
#   GH_TOKEN              GitHub PAT            (prompted if not set)
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BRANCH="${ANGELCLAW_BRANCH:-main}"
INSTALL_DIR="${ANGELCLAW_DIR:-$HOME/AngelClaw}"
TENANT_ID="${ANGELCLAW_TENANT_ID:-default}"
CLOUD_URL="${ANGELCLAW_CLOUD_URL:-http://cloud:8500}"
LLM="${LLM_ENABLED:-false}"
FORCE="${ANGELCLAW_FORCE:-false}"

TOTAL_STEPS=8
STEP=0

# Colors
G='\033[92m' Y='\033[93m' R='\033[91m' C='\033[96m' B='\033[1m' N='\033[0m'

step() { STEP=$((STEP+1)); echo -e "${C}[$STEP/$TOTAL_STEPS]${N} $1"; }
ok()   { echo -e "  ${G}[OK]${N} $1"; }
warn() { echo -e "  ${Y}[!]${N} $1"; }
err()  { echo -e "  ${R}[X]${N} $1"; }

# Cleanup trap
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo ""
        err "Installation failed (exit code $exit_code). Check the output above."
        echo "  For help: https://github.com/Senior3514/AngelClaw/issues"
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo ""
echo -e "${B}${C}================================================${N}"
echo -e "${B}${C}  AngelClaw AGI Guardian -- macOS Installer${N}"
echo -e "${B}${C}  V3.0.0 -- Dominion${N}"
echo -e "${B}${C}================================================${N}"
echo ""

echo "  Tenant ID    : $TENANT_ID"
echo "  Install dir  : $INSTALL_DIR"
echo "  Branch       : $BRANCH"
echo ""

# GitHub credentials (private repo) -- read from /dev/tty so curl|bash works
if [ -z "${GH_USER:-}" ]; then
  printf "  GitHub username: " ; read -r GH_USER < /dev/tty
fi
if [ -z "${GH_TOKEN:-}" ]; then
  printf "  GitHub PAT (token): " ; read -r GH_TOKEN < /dev/tty
fi
REPO="https://${GH_USER}:${GH_TOKEN}@github.com/Senior3514/AngelClaw.git"
ok "Credentials set for github.com/Senior3514/AngelClaw"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Check/Install Homebrew
# ---------------------------------------------------------------------------
step "Checking Homebrew..."

if command -v brew &>/dev/null; then
  ok "Homebrew found."
else
  warn "Homebrew is not installed. Installing automatically..."
  NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  # Add Homebrew to PATH for Apple Silicon Macs
  if [ -f /opt/homebrew/bin/brew ]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [ -f /usr/local/bin/brew ]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi
  if command -v brew &>/dev/null; then
    ok "Homebrew installed."
  else
    err "Homebrew installation failed. Install manually: https://brew.sh"
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# Step 2: Check/Install Docker Desktop
# ---------------------------------------------------------------------------
step "Checking Docker..."

if command -v docker &>/dev/null; then
  DOCKER_VER=$(docker --version 2>/dev/null || echo "unknown")
  ok "Docker found: $DOCKER_VER"
else
  warn "Docker Desktop is not installed. Installing via Homebrew..."
  brew install --cask docker
  echo ""
  echo -e "  ${Y}Docker Desktop has been installed but needs to be started.${N}"
  echo -e "  ${Y}Opening Docker Desktop now...${N}"
  open -a Docker 2>/dev/null || true
  echo -e "  ${C}Waiting for Docker to start (up to 90s)...${N}"
  WAITED=0
  while [ $WAITED -lt 90 ]; do
    sleep 5
    WAITED=$((WAITED + 5))
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
      break
    fi
    echo -e "  ${Y}Waiting... (${WAITED}s)${N}"
  done
  if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    ok "Docker Desktop is running."
  else
    echo ""
    echo -e "  ${Y}================================================${N}"
    echo -e "  ${Y}Docker Desktop was installed but is still starting.${N}"
    echo -e "  ${Y}Please wait for Docker Desktop to fully load,${N}"
    echo -e "  ${Y}then re-run this installer.${N}"
    echo -e "  ${Y}================================================${N}"
    echo ""
    exit 0
  fi
fi

# Verify Docker daemon is running
if ! docker info &>/dev/null 2>&1; then
  warn "Docker daemon is not running. Attempting to start Docker Desktop..."
  open -a Docker 2>/dev/null || true
  echo -e "  ${C}Waiting for Docker to start (up to 60s)...${N}"
  WAITED=0
  while [ $WAITED -lt 60 ]; do
    sleep 5
    WAITED=$((WAITED + 5))
    if docker info &>/dev/null 2>&1; then break; fi
    echo -e "  ${Y}Waiting... (${WAITED}s)${N}"
  done
  if ! docker info &>/dev/null 2>&1; then
    err "Docker daemon is not running. Please start Docker Desktop and re-run this script."
    exit 1
  fi
fi
ok "Docker daemon is running."

# ---------------------------------------------------------------------------
# Step 3: Check docker compose
# ---------------------------------------------------------------------------
step "Checking docker compose..."

DC_CMD=""
if docker compose version &>/dev/null 2>&1; then
  DC_VER=$(docker compose version 2>/dev/null || echo "unknown")
  ok "docker compose found: $DC_VER"
  DC_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
  DC_VER=$(docker-compose --version 2>/dev/null || echo "unknown")
  ok "docker-compose found: $DC_VER"
  DC_CMD="docker-compose"
else
  err "docker compose is not available."
  echo "  Docker Desktop should include docker compose. Please update Docker Desktop."
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 4: Check git + network
# ---------------------------------------------------------------------------
step "Checking prerequisites..."

if ! command -v git &>/dev/null; then
  echo -e "  ${C}Installing git via Homebrew...${N}"
  brew install git
  ok "git installed."
else
  ok "git found."
fi

# Quick network check
if curl -sf --max-time 5 https://github.com >/dev/null 2>&1; then
  ok "Network connectivity verified."
else
  warn "Cannot reach github.com -- check your internet connection."
fi

# ---------------------------------------------------------------------------
# Step 5: Clone or update repo
# ---------------------------------------------------------------------------
step "Setting up AngelClaw at $INSTALL_DIR..."

if [ "$FORCE" = "true" ] && [ -d "$INSTALL_DIR" ]; then
  warn "ANGELCLAW_FORCE=true -- removing existing installation..."
  rm -rf "$INSTALL_DIR"
fi

if [ -d "$INSTALL_DIR/.git" ]; then
  ok "Existing installation found -- pulling latest..."
  cd "$INSTALL_DIR"
  git fetch origin
  git checkout "$BRANCH"
  git pull origin "$BRANCH"
  ok "Repository updated."
else
  if [ -d "$INSTALL_DIR" ]; then
    warn "Directory exists but is not a git repo -- removing and re-cloning..."
    rm -rf "$INSTALL_DIR"
  fi
  echo -e "  ${C}Cloning repository...${N}"
  git clone --branch "$BRANCH" "$REPO" "$INSTALL_DIR"
  ok "Repository cloned."
fi

cd "$INSTALL_DIR"

# ---------------------------------------------------------------------------
# Step 6: Write config
# ---------------------------------------------------------------------------
step "Writing configuration..."

CONFIG_FILE="$INSTALL_DIR/ops/config/angelclaw.env"
mkdir -p "$INSTALL_DIR/ops/config"

cat > "$CONFIG_FILE" <<ENVEOF
# AngelClaw AGI Guardian -- generated by installer on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
ANGELCLAW_TENANT_ID=${TENANT_ID}
ANGELCLAW_CLOUD_URL=${CLOUD_URL}
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
step "Building and starting AngelClaw stack..."

cd "$INSTALL_DIR/ops"
$DC_CMD up -d --build

ok "Containers started."

# ---------------------------------------------------------------------------
# Step 8: Health check with retries
# ---------------------------------------------------------------------------
step "Verifying services..."

echo -e "  ${C}Waiting for startup...${N}"
sleep 10

for attempt in 1 2 3; do
  if curl -sf --max-time 5 http://127.0.0.1:8400/health >/dev/null 2>&1; then
    ok "ANGELNODE is healthy (port 8400)"
    break
  else
    if [ "$attempt" -lt 3 ]; then
      echo -e "  ${Y}Retry $attempt/3...${N}"
      sleep 5
    else
      warn "ANGELNODE health check failed -- it may still be starting."
    fi
  fi
done

if curl -sf --max-time 5 http://127.0.0.1:8500/health >/dev/null 2>&1; then
  ok "Cloud API is healthy (port 8500)"
else
  warn "Cloud API health check failed -- it may still be starting."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${B}${G}================================================${N}"
echo -e "${B}${G}  AngelClaw AGI Guardian -- Installed on macOS!${N}"
echo -e "${B}${G}================================================${N}"
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
echo -e "  ${Y}Default login: admin / fzMiSbDRGylsWrsaljMv7UxzrwdXCdTe${N}"
echo -e "  ${Y}Change the password immediately after first login!${N}"
echo ""
echo "  Useful commands:"
echo "    docker ps                              # check containers"
echo "    docker logs angelclaw-angelnode-1 -f   # follow node logs"
echo "    docker logs angelclaw-cloud-1 -f       # follow cloud logs"
echo ""
echo "  Multi-tenancy:"
echo "    Each ANGELNODE uses a Tenant ID to isolate data."
echo "    Set ANGELCLAW_TENANT_ID=<name> to add tenants."
echo ""

if [ "$LLM" = "true" ]; then
  echo "  LLM proxy is enabled. Pull a model:"
  echo "    cd $INSTALL_DIR/ops && $DC_CMD exec ollama ollama pull llama3"
  echo ""
fi

echo -e "  ${C}AngelClaw V3.0.0 -- Dominion -- guardian angel, not gatekeeper.${N}"
echo ""
