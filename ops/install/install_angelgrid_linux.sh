#!/usr/bin/env bash
# ============================================================================
# AngelClaw AGI Guardian -- Linux Installer (V2.0.0) [LEGACY]
#
# DEPRECATED: This script redirects to install_angelclaw_linux.sh
# Use install_angelclaw_linux.sh directly for new installations.
# ============================================================================

set -euo pipefail

C='\033[96m' Y='\033[93m' R='\033[91m' N='\033[0m'

echo ""
echo -e "${Y}[AngelClaw] NOTE: install_angelgrid_linux.sh is deprecated.${N}"
echo -e "${Y}[AngelClaw] Redirecting to install_angelclaw_linux.sh...${N}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NEW_SCRIPT="$SCRIPT_DIR/install_angelclaw_linux.sh"

if [ -f "$NEW_SCRIPT" ]; then
    exec bash "$NEW_SCRIPT"
else
    echo -e "${R}[X] Could not find install_angelclaw_linux.sh at $NEW_SCRIPT${N}"
    echo ""
    echo "  Download the latest installer:"
    echo "    curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash"
    exit 1
fi
