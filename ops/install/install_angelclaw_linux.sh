#!/usr/bin/env bash
# ============================================================================
# AngelClaw AGI Guardian -- Linux Server Installer (V2.2.1)
#
# Installs the full AngelClaw stack (ANGELNODE + Cloud + Ollama) on a Linux
# server using Docker Compose + systemd. All dependencies are auto-installed.
#
# ONE-LINE INSTALL:
#   curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash
#
# Or download and run manually:
#   chmod +x install_angelclaw_linux.sh
#   ./install_angelclaw_linux.sh
#
# Optional environment variables:
#   ANGELCLAW_REPO        Git repo URL       (default: https://github.com/Senior3514/AngelClaw.git)
#   ANGELCLAW_BRANCH      Branch to checkout  (default: main)
#   ANGELCLAW_DIR         Install directory    (default: /root/AngelClaw)
#   ANGELCLAW_TENANT_ID   Tenant identifier    (default: default)
#   ANGELCLAW_CLOUD_URL   Cloud URL for agents (default: http://cloud:8500)
#   LLM_ENABLED           Enable LLM proxy     (default: false)
#   ANGELCLAW_FORCE       Force clean reinstall (default: false)
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REPO="${ANGELCLAW_REPO:-https://github.com/Senior3514/AngelClaw.git}"
BRANCH="${ANGELCLAW_BRANCH:-main}"
INSTALL_DIR="${ANGELCLAW_DIR:-/root/AngelClaw}"
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
echo -e "${B}${C}  AngelClaw AGI Guardian -- Linux Server Installer${N}"
echo -e "${B}${C}  V2.2.1 -- Angel Legion${N}"
echo -e "${B}${C}================================================${N}"
echo ""

# Must be root
if [ "$(id -u)" -ne 0 ]; then
  err "This installer must be run as root (or with sudo)."
  exit 1
fi

# Detect package manager
install_pkg() {
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq "$@"
    elif command -v dnf &>/dev/null; then
        dnf install -y -q "$@"
    elif command -v yum &>/dev/null; then
        yum install -y -q "$@"
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm "$@"
    elif command -v apk &>/dev/null; then
        apk add --quiet "$@"
    else
        err "No supported package manager found. Install $* manually."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Step 1: Install Docker (auto-install if missing)
# ---------------------------------------------------------------------------
step "Checking Docker..."

if command -v docker &>/dev/null; then
  DOCKER_VER=$(docker --version 2>/dev/null || echo "unknown")
  ok "Docker found: $DOCKER_VER"
else
  warn "Docker is not installed. Installing automatically..."
  if command -v curl &>/dev/null; then
    curl -fsSL https://get.docker.com | sh
  elif command -v wget &>/dev/null; then
    wget -qO- https://get.docker.com | sh
  else
    install_pkg curl
    curl -fsSL https://get.docker.com | sh
  fi
  systemctl enable docker
  systemctl start docker
  ok "Docker installed and started."
fi

# Ensure Docker is running
if ! docker info &>/dev/null 2>&1; then
  systemctl start docker 2>/dev/null || true
  sleep 3
  if ! docker info &>/dev/null 2>&1; then
    err "Docker daemon failed to start. Check: systemctl status docker"
    exit 1
  fi
fi
ok "Docker daemon is running."

# ---------------------------------------------------------------------------
# Step 2: Check docker compose
# ---------------------------------------------------------------------------
step "Checking docker compose..."

DC_CMD=""
if docker compose version &>/dev/null 2>&1; then
  DC_VER=$(docker compose version 2>/dev/null || echo "unknown")
  ok "docker compose (v2 plugin) found: $DC_VER"
  DC_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
  DC_VER=$(docker-compose --version 2>/dev/null || echo "unknown")
  ok "docker-compose found: $DC_VER"
  DC_CMD="docker-compose"
else
  warn "docker compose not found. Installing docker-compose-plugin..."
  if command -v apt-get &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq docker-compose-plugin 2>/dev/null || true
  fi
  # Re-check after install attempt
  if docker compose version &>/dev/null 2>&1; then
    DC_CMD="docker compose"
    ok "docker compose plugin installed."
  else
    # Fallback: install via pip
    warn "Plugin not available. Installing docker-compose via pip..."
    if ! command -v pip3 &>/dev/null; then
      install_pkg python3-pip
    fi
    pip3 install docker-compose --break-system-packages 2>/dev/null || pip3 install docker-compose
    DC_CMD="docker-compose"
    ok "docker-compose installed."
  fi
fi

# ---------------------------------------------------------------------------
# Step 3: Check git + curl
# ---------------------------------------------------------------------------
step "Checking prerequisites..."

if ! command -v git &>/dev/null; then
  echo -e "  ${C}Installing git...${N}"
  install_pkg git
  ok "git installed."
else
  ok "git found."
fi

if ! command -v curl &>/dev/null; then
  install_pkg curl
fi

# Quick network check
if curl -sf --max-time 5 https://github.com >/dev/null 2>&1; then
  ok "Network connectivity verified."
else
  warn "Cannot reach github.com -- check your internet connection."
fi

# ---------------------------------------------------------------------------
# Step 4: Clone or update repo
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
# Step 5: Write config
# ---------------------------------------------------------------------------
step "Writing configuration..."

CONFIG_FILE="$INSTALL_DIR/ops/config/angelclaw.env"
mkdir -p "$INSTALL_DIR/ops/config"

cat > "$CONFIG_FILE" <<ENVEOF
# AngelClaw AGI Guardian -- generated by installer on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
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
# Step 6: Build and start containers
# ---------------------------------------------------------------------------
step "Building and starting AngelClaw stack..."

cd "$INSTALL_DIR/ops"
$DC_CMD up -d --build

ok "Containers started."

# ---------------------------------------------------------------------------
# Step 7: Install systemd service
# ---------------------------------------------------------------------------
step "Installing systemd service..."

# Resolve the full binary path for systemd
if [ "$DC_CMD" = "docker compose" ]; then
  DC_EXEC_START="$(command -v docker) compose up -d"
  DC_EXEC_STOP="$(command -v docker) compose down"
else
  DC_EXEC_START="$(command -v docker-compose) up -d"
  DC_EXEC_STOP="$(command -v docker-compose) down"
fi

cat > /etc/systemd/system/angelclaw.service <<SVCEOF
[Unit]
Description=AngelClaw AGI Guardian
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${INSTALL_DIR}/ops
ExecStart=${DC_EXEC_START}
ExecStop=${DC_EXEC_STOP}
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable angelclaw.service
ok "systemd service enabled (angelclaw.service)."

# ---------------------------------------------------------------------------
# Step 8: Health check with retries
# ---------------------------------------------------------------------------
step "Verifying services..."

echo -e "  ${C}Waiting for startup...${N}"
sleep 10

HEALTHY=true
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
      HEALTHY=false
    fi
  fi
done

if curl -sf --max-time 5 http://127.0.0.1:8500/health >/dev/null 2>&1; then
  ok "Cloud API is healthy (port 8500)"
else
  warn "Cloud API health check failed -- it may still be starting."
  HEALTHY=false
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${B}${G}================================================${N}"
echo -e "${B}${G}  AngelClaw AGI Guardian -- Installed!${N}"
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
echo "  Default login: admin / angelclaw (change immediately!)"
echo ""
echo "  Useful commands:"
echo "    systemctl status angelclaw          # check stack status"
echo "    systemctl restart angelclaw         # restart"
echo "    journalctl -u angelclaw -f          # follow logs"
echo "    $INSTALL_DIR/ops/cli/angelclawctl status    # CLI status"
echo ""
echo "  Connect clients (Windows/macOS):"
echo "    Point them to: http://YOUR-VPS-IP:8500"
echo ""
echo "  Remote access (from tablet/phone/laptop):"
echo "    ssh -L 8500:127.0.0.1:8500 root@YOUR-VPS-IP"
echo "    Then open: http://localhost:8500/ui"
echo ""

if [ "$LLM" = "true" ]; then
  echo "  LLM proxy is enabled. Pull a model:"
  echo "    cd $INSTALL_DIR/ops && $DC_CMD exec ollama ollama pull llama3"
  echo ""
fi

echo -e "  ${C}AngelClaw V2.2.1 -- Angel Legion -- guardian angel, not gatekeeper.${N}"
echo ""
