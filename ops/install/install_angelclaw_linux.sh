#!/usr/bin/env bash
# ============================================================================
# AngelClaw AGI Guardian — Linux Installer (V1.1.0)
#
# Installs the full AngelClaw stack (ANGELNODE + Cloud + Ollama) on a Linux
# server using Docker Compose + systemd.
#
# Usage:
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

# Colors
G='\033[92m' Y='\033[93m' R='\033[91m' C='\033[96m' B='\033[1m' N='\033[0m'

log()  { echo -e "${C}[AngelClaw]${N} $1"; }
ok()   { echo -e "${G}[OK]${N} $1"; }
warn() { echo -e "${Y}[!]${N} $1"; }
err()  { echo -e "${R}[X]${N} $1"; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
echo ""
echo -e "${B}${C}+================================================+${N}"
echo -e "${B}${C}|   AngelClaw AGI Guardian — Linux Installer      |${N}"
echo -e "${B}${C}|   V1.1.0 — Guardian Angel, Not Gatekeeper       |${N}"
echo -e "${B}${C}+================================================+${N}"
echo ""

# Must be root
if [ "$(id -u)" -ne 0 ]; then
  err "This installer must be run as root (or with sudo)."
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Check Docker
# ---------------------------------------------------------------------------
log "Checking Docker..."

if command -v docker &>/dev/null; then
  DOCKER_VER=$(docker --version 2>/dev/null || echo "unknown")
  ok "Docker found: $DOCKER_VER"
else
  warn "Docker is not installed."
  echo ""
  echo "  Install Docker with the official convenience script:"
  echo ""
  echo "    curl -fsSL https://get.docker.com | sh"
  echo ""
  read -rp "  Install Docker now? [y/N] " INSTALL_DOCKER
  if [[ "$INSTALL_DOCKER" =~ ^[Yy]$ ]]; then
    log "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
    ok "Docker installed and started."
  else
    err "Docker is required. Please install it and re-run this script."
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# Step 2: Check docker-compose
# ---------------------------------------------------------------------------
log "Checking docker-compose..."

if docker compose version &>/dev/null 2>&1; then
  DC_VER=$(docker compose version 2>/dev/null || echo "unknown")
  ok "docker compose (v2 plugin) found: $DC_VER"
  DC_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
  DC_VER=$(docker-compose --version 2>/dev/null || echo "unknown")
  ok "docker-compose found: $DC_VER"
  DC_CMD="docker-compose"
else
  warn "docker-compose is not installed."
  log "Installing docker-compose via pip..."
  if command -v pip3 &>/dev/null; then
    pip3 install docker-compose --break-system-packages 2>/dev/null || pip3 install docker-compose
  elif command -v pip &>/dev/null; then
    pip install docker-compose --break-system-packages 2>/dev/null || pip install docker-compose
  else
    apt-get update -qq && apt-get install -y -qq python3-pip
    pip3 install docker-compose --break-system-packages 2>/dev/null || pip3 install docker-compose
  fi
  DC_CMD="docker-compose"
  ok "docker-compose installed."
fi

# ---------------------------------------------------------------------------
# Step 3: Check git
# ---------------------------------------------------------------------------
if ! command -v git &>/dev/null; then
  log "Installing git..."
  apt-get update -qq && apt-get install -y -qq git curl
  ok "git installed."
fi

# ---------------------------------------------------------------------------
# Step 4: Clone or update repo
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
# Step 5: Write config
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
# Step 6: Build and start containers
# ---------------------------------------------------------------------------
log "Building and starting AngelClaw stack..."

cd "$INSTALL_DIR/ops"
$DC_CMD up -d --build

ok "Containers started."

# ---------------------------------------------------------------------------
# Step 7: Install systemd units
# ---------------------------------------------------------------------------
log "Installing systemd services..."

# Create a simple systemd unit for AngelClaw
cat > /etc/systemd/system/angelclaw.service <<SVCEOF
[Unit]
Description=AngelClaw AGI Guardian
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${INSTALL_DIR}/ops
ExecStart=$(command -v ${DC_CMD%% *}) ${DC_CMD#* } up -d
ExecStop=$(command -v ${DC_CMD%% *}) ${DC_CMD#* } down
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable angelclaw.service
ok "systemd service enabled."

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
echo -e "${B}${G}|   AngelClaw AGI Guardian installed!              |${N}"
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
echo "    systemctl status angelclaw          # check stack status"
echo "    systemctl restart angelclaw         # restart"
echo "    journalctl -u angelclaw -f          # follow logs"
echo "    $INSTALL_DIR/ops/cli/angelclawctl status    # CLI status"
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

echo -e "  ${C}AngelClaw AGI Guardian — guardian angel, not gatekeeper.${N}"
echo ""
