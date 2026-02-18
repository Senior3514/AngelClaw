# AngelClaw AGI Guardian -- Installation Guide (V2.0.0)

## Overview

AngelClaw V2.0.0 deploys as three containers running the **Angel Legion** -- a 10-agent
autonomous security swarm:

| Component | Port | Description |
|-----------|------|-------------|
| **ANGELNODE** | 8400 | Local policy engine (lightweight agent) |
| **Cloud API** | 8500 | Central management, Angel Legion orchestrator, dashboard, AI chat |
| **Ollama** | internal | Optional local LLM (no host port) |

All components bind to `127.0.0.1` by default -- secure out of the box.

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Docker | 20.10+ | Docker Desktop (macOS/Windows) or Docker Engine (Linux) |
| Docker Compose | v2+ | Included with Docker Desktop; `docker compose` plugin on Linux |
| Git | 2.x+ | For cloning the repository |
| Python | 3.11+ | Only needed for local development (not Docker) |

---

## Linux (Full Stack)

### Install -- One Command

```bash
curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash
```

Installs Docker (if missing), clones the repo, builds all 3 containers (ANGELNODE + Cloud + Ollama), registers systemd service for auto-start on boot.

**Manual install:**

```bash
git clone https://github.com/Senior3514/AngelClaw.git /root/AngelClaw
cd /root/AngelClaw/ops
docker compose up -d --build
```

**Force clean reinstall (removes existing install first):**

```bash
ANGELCLAW_FORCE=true curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash
```

### Uninstall -- One Command

```bash
curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/uninstall_angelclaw_linux.sh | bash
```

Stops containers, removes systemd service, Docker images, volumes, and the install directory.

**Keep files but remove everything else:**

```bash
ANGELCLAW_KEEP_DATA=true curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/uninstall_angelclaw_linux.sh | bash
```

### Clean (keep files, reset containers)

```bash
cd /root/AngelClaw/ops && docker compose down --volumes --remove-orphans
docker system prune -f
```

### Reinstall -- One Command

```bash
curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/uninstall_angelclaw_linux.sh | bash && curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash
```

### Verify

```bash
curl http://127.0.0.1:8400/health   # ANGELNODE
curl http://127.0.0.1:8500/health   # Cloud API
curl http://127.0.0.1:8500/ui       # Dashboard
systemctl status angelclaw          # Service status
journalctl -u angelclaw -f          # Follow logs
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANGELCLAW_DIR` | `/root/AngelClaw` | Install directory |
| `ANGELCLAW_TENANT_ID` | `default` | Tenant identifier |
| `ANGELCLAW_CLOUD_URL` | `http://cloud:8500` | Cloud URL for agents |
| `ANGELCLAW_BIND_HOST` | `127.0.0.1` | API bind address |
| `ANGELCLAW_BIND_PORT` | `8500` | API port |
| `ANGELCLAW_AUTH_ENABLED` | `true` | Enable JWT authentication |
| `ANGELCLAW_FORCE` | `false` | Force clean reinstall |
| `LLM_ENABLED` | `false` | Enable LLM proxy |
| `LLM_MODEL` | `llama3` | Ollama model name |

---

## macOS (Full Stack)

### Install -- One Command

```bash
curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_macos.sh | bash
```

Installs Homebrew + Docker Desktop (if missing), clones the repo, builds the full stack.

**Manual install:**

```bash
brew install --cask docker          # Install Docker Desktop
git clone https://github.com/Senior3514/AngelClaw.git ~/AngelClaw
cd ~/AngelClaw/ops
docker compose up -d --build
```

**Force clean reinstall:**

```bash
ANGELCLAW_FORCE=true curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_macos.sh | bash
```

### Uninstall -- One Command

```bash
curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/uninstall_angelclaw_macos.sh | bash
```

Stops containers, removes Docker images, volumes, and the install directory.

**Keep files but remove everything else:**

```bash
ANGELCLAW_KEEP_DATA=true curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/uninstall_angelclaw_macos.sh | bash
```

### Clean (keep files, reset containers)

```bash
cd ~/AngelClaw/ops && docker compose down --volumes --remove-orphans
docker system prune -f
```

### Reinstall -- One Command

```bash
curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/uninstall_angelclaw_macos.sh | bash && curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_macos.sh | bash
```

### Verify

```bash
curl http://127.0.0.1:8400/health   # ANGELNODE
curl http://127.0.0.1:8500/health   # Cloud API
open http://127.0.0.1:8500/ui       # Dashboard
```

---

## Windows (ANGELNODE Agent Only)

Windows installs **ANGELNODE only** (the lightweight agent). The Cloud backend runs on your Linux/macOS server. Replace `YOUR-VPS-IP` with your server's IP.

**Prerequisite:** [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/) must be installed and running.

### Install

PowerShell (as Administrator):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
git clone https://github.com/Senior3514/AngelClaw.git C:\AngelClaw
C:\AngelClaw\ops\install\install_angelclaw_windows.ps1 -CloudUrl "http://YOUR-VPS-IP:8500"
```

**Already installed? The installer auto-detects and updates:**

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
C:\AngelClaw\ops\install\install_angelclaw_windows.ps1 -CloudUrl "http://YOUR-VPS-IP:8500"
```

**Force clean reinstall:**

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
C:\AngelClaw\ops\install\install_angelclaw_windows.ps1 -CloudUrl "http://YOUR-VPS-IP:8500" -Force
```

### Uninstall

PowerShell (as Administrator):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
C:\AngelClaw\ops\install\uninstall_angelclaw_windows.ps1
```

**Keep files but remove everything else:**

```powershell
C:\AngelClaw\ops\install\uninstall_angelclaw_windows.ps1 -KeepData
```

### Clean (keep files, reset containers)

```powershell
cd C:\AngelClaw\ops; docker compose down --volumes --remove-orphans
docker system prune -f
```

### Reinstall

PowerShell (as Administrator):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
C:\AngelClaw\ops\install\uninstall_angelclaw_windows.ps1
git clone https://github.com/Senior3514/AngelClaw.git C:\AngelClaw
C:\AngelClaw\ops\install\install_angelclaw_windows.ps1 -CloudUrl "http://YOUR-VPS-IP:8500"
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-CloudUrl` | `http://your-cloud-server:8500` | Your VPS Cloud API URL |
| `-TenantId` | `default` | Tenant identifier |
| `-InstallDir` | `C:\AngelClaw` | Install directory |
| `-Branch` | `main` | Git branch to checkout |
| `-Force` | `$false` | Force clean reinstall |

### Verify

```powershell
curl http://127.0.0.1:8400/health
curl http://127.0.0.1:8400/status
docker ps
docker logs angelclaw-angelnode-1
```

---

## Remote UI Access (Browser / Tablet)

AngelClaw Cloud serves a full web dashboard at `/ui`.

### Option 1: SSH Tunnel (Recommended)

Most secure -- no auth bypass needed:

```bash
ssh -L 8500:127.0.0.1:8500 root@YOUR-VPS-IP
```

Then open `http://localhost:8500/ui` in your browser.

### Option 2: Reverse Proxy (nginx)

For persistent remote access with HTTPS:

```nginx
server {
    listen 443 ssl;
    server_name angelclaw.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/angelclaw.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/angelclaw.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8500;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Ensure `ANGELCLAW_AUTH_ENABLED=true` (default) when exposing to the internet.

---

## Development Setup

```bash
# Clone
git clone https://github.com/Senior3514/AngelClaw.git
cd AngelClaw

# Install dependencies
pip install -e ".[dev,cloud]"

# Run ANGELNODE (terminal 1)
uvicorn angelnode.core.server:app --host 127.0.0.1 --port 8400

# Run Cloud API (terminal 2)
uvicorn cloud.api.server:app --host 127.0.0.1 --port 8500
```

---

## Default Credentials

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `angelclaw` |
| Role | `admin` |

**Change the default password immediately** after first login via the UI or:

```bash
curl -X POST http://127.0.0.1:8500/api/v1/auth/change-password \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"current_password":"angelclaw","new_password":"YOUR_STRONG_PASSWORD"}'
```

---

## Troubleshooting

### Windows: PowerShell parse errors with special characters

**Symptom:** Errors like `Unexpected token` or garbled characters (`a]"`) when running `.ps1` scripts.

**Cause:** PowerShell 5.x reads files as ANSI by default. Non-ASCII characters (em dashes, etc.) in UTF-8 files corrupt the parser.

**Fix:** V2.0.0 scripts are now pure ASCII. Pull the latest version:

```powershell
cd C:\AngelClaw; git pull origin main
```

### Windows: "destination path already exists and is not an empty directory"

**Symptom:** `git clone` fails because `C:\AngelClaw` already exists.

**Fix:** The installer handles this automatically. Just run:

```powershell
C:\AngelClaw\ops\install\install_angelclaw_windows.ps1 -CloudUrl "http://YOUR-VPS-IP:8500"
```

Or force a clean reinstall:

```powershell
C:\AngelClaw\ops\install\install_angelclaw_windows.ps1 -CloudUrl "http://YOUR-VPS-IP:8500" -Force
```

### Health check fails after install

**Symptom:** Health check returns failure during installation.

**Fix:** Containers may need more time. Wait 30 seconds and check manually:

```bash
curl http://127.0.0.1:8400/health   # ANGELNODE
curl http://127.0.0.1:8500/health   # Cloud API
docker ps                           # Check container status
docker logs angelclaw-angelnode-1   # Check for errors
```

### Docker daemon not running

**Symptom:** "Docker daemon is not running" error.

**Fix:**
- **Linux:** `systemctl start docker`
- **macOS:** Open Docker Desktop from Applications
- **Windows:** Start Docker Desktop from Start menu, wait for it to fully load

### Port conflicts

**Symptom:** Container fails to start, port already in use.

**Fix:** Check what is using the port and stop it:

```bash
# Linux/macOS
lsof -i :8400
lsof -i :8500

# Windows (PowerShell)
netstat -ano | findstr :8400
netstat -ano | findstr :8500
```

---

## Quick Reference

| What | Command |
|------|---------|
| Install (Linux) | `curl -sSL .../install_angelclaw_linux.sh \| bash` |
| Install (macOS) | `curl -sSL .../install_angelclaw_macos.sh \| bash` |
| Install (Windows) | `.\install_angelclaw_windows.ps1 -CloudUrl "..."` |
| Uninstall (Linux) | `curl -sSL .../uninstall_angelclaw_linux.sh \| bash` |
| Uninstall (macOS) | `curl -sSL .../uninstall_angelclaw_macos.sh \| bash` |
| Uninstall (Windows) | `.\uninstall_angelclaw_windows.ps1` |
| Force reinstall | Add `ANGELCLAW_FORCE=true` (Linux/macOS) or `-Force` (Windows) |
| Dashboard | `http://127.0.0.1:8500/ui` |
| ANGELNODE health | `curl http://127.0.0.1:8400/health` |
| Cloud API health | `curl http://127.0.0.1:8500/health` |
| CLI status | `./ops/cli/angelclawctl status` |
| Remote access | `ssh -L 8500:127.0.0.1:8500 root@YOUR-VPS-IP` |

---

## Architecture

```
                    +-------------------+
                    |   Browser / CLI   |
                    +--------+----------+
                             |
                    +--------v----------+
                    |  AngelClaw Cloud  |  :8500
                    |  (FastAPI + DB)   |
                    |  - Seraph Brain   |
                    |  - Angel Legion   |
                    |  - Shield         |
                    |  - Auth/RBAC      |
                    +---+----------+----+
                        |          |
              +---------+    +-----+-------+
              |              |             |
     +--------v---+   +-----v-----+  +----v------+
     | ANGELNODE   |   | Ollama    |  | Wazuh     |
     | :8400       |   | (internal)|  | (optional)|
     +-------------+   +-----------+  +-----------+

     Angel Legion (10 agents inside Cloud):
     +----------+----------+----------+----------+
     |  Vigil   |Net Warden|Glass Eye |Tool Smith|
     |(Sentinel)|(Network) |(Browser) |(Toolchain|
     +----------+----------+----------+----------+
     |Chronicle |Vault Keep|Drift Watch| Response |
     |(Timeline)|(Secrets) |(Behavior)|          |
     +----------+----------+----------+----------+
     | Forensic |  Audit   |          |          |
     +----------+----------+----------+----------+
```
