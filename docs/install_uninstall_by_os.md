# AngelClaw — Installation & Uninstallation Guide

## Prerequisites
- Python 3.11+ (or Docker)
- Git
- 512MB RAM minimum (1GB recommended)

## Linux (Ubuntu/Debian, RHEL/Fedora, Arch)

### One-Command Install
```bash
curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash
```

### Manual Install
```bash
git clone https://github.com/Senior3514/AngelClaw.git /opt/angelclaw
cd /opt/angelclaw
python3 -m venv venv && source venv/bin/activate
pip install -e ".[cloud,dev]"
python3 -m uvicorn cloud.api.server:app --host 127.0.0.1 --port 8500
```

### Systemd Service
```bash
sudo cp ops/systemd/angelclaw.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now angelclaw
```

### Uninstall
```bash
curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/uninstall_angelclaw_linux.sh | bash
```
Or manually:
```bash
sudo systemctl stop angelclaw 2>/dev/null
sudo systemctl disable angelclaw 2>/dev/null
sudo rm -f /etc/systemd/system/angelclaw.service
rm -rf /opt/angelclaw
# Set ANGELCLAW_KEEP_DATA=1 to preserve data directories
```

## macOS

### One-Command Install
```bash
curl -fsSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_macos.sh | bash
```

### Manual Install
```bash
git clone https://github.com/Senior3514/AngelClaw.git ~/angelclaw
cd ~/angelclaw
python3 -m venv venv && source venv/bin/activate
pip install -e ".[cloud,dev]"
python3 -m uvicorn cloud.api.server:app --host 127.0.0.1 --port 8500
```

### Uninstall
```bash
rm -rf ~/angelclaw
```

## Windows

### One-Command Install (PowerShell as Administrator)
```powershell
irm https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_windows.ps1 | iex
```

### Manual Install
```powershell
git clone https://github.com/Senior3514/AngelClaw.git C:\AngelClaw
cd C:\AngelClaw
python -m venv venv
.\venv\Scripts\activate
pip install -e ".[cloud,dev]"
python -m uvicorn cloud.api.server:app --host 127.0.0.1 --port 8500
```

### Uninstall
```powershell
Remove-Item -Recurse -Force C:\AngelClaw
```

## Docker (All Platforms)

### Install & Run
```bash
git clone https://github.com/Senior3514/AngelClaw.git
cd AngelClaw
docker compose up -d
```

### Stop & Remove
```bash
docker compose down
# Add -v to also remove volumes (data)
docker compose down -v
```

## Mobile Access (iOS / Android / DuckDuckGo)

Mobile browsers do not support extensions. Use the web UI instead:

1. Open your mobile browser
2. Navigate to `https://your-angelclaw-host:8500/ui`
3. Log in with your credentials
4. **iOS Safari**: Tap Share > Add to Home Screen (PWA install)
5. **Android Chrome**: Tap menu > Add to Home Screen (PWA install)
6. **DuckDuckGo**: Bookmark the page for quick access

The AngelClaw console is fully responsive and works well on all mobile devices.

## Browser Extensions

### Chrome / Edge / Brave / Opera / Arc
1. Open `chrome://extensions/` (or equivalent)
2. Enable Developer mode
3. Click "Load unpacked" and select `extensions/chrome/`
4. Configure API URL and auth token in the extension popup

### DuckDuckGo Desktop Browser
1. Open `duckduckgo://extensions/`
2. Enable Developer mode
3. Click "Load unpacked" and select `extensions/chrome/`

See `extensions/README.md` and `extensions/duckduckgo/README.md` for details.

## Verification

After installation, verify with:
```bash
curl http://localhost:8500/health
# Expected: {"status":"ok","version":"3.0.0",...}
```

Run tests:
```bash
python3 -m pytest tests/ -q
# Expected: 1758+ passed
```
