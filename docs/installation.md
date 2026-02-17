# AngelClaw AGI Guardian — Installation Guide

## Overview

AngelClaw deploys as three components:

| Component | Port | Description |
|-----------|------|-------------|
| **ANGELNODE** | 8400 | Local policy engine (lightweight agent) |
| **Cloud API** | 8500 | Central management, dashboard, AI chat |
| **Ollama** | internal | Optional local LLM (no host port) |

All components bind to `127.0.0.1` by default — secure out of the box.

---

## Linux Full Stack (Recommended)

### Quick Install

On a fresh Ubuntu/Debian server (as root):

```bash
curl -sSL https://raw.githubusercontent.com/Senior3514/AngelClaw/main/ops/install/install_angelclaw_linux.sh | bash
```

### Manual Install

```bash
git clone https://github.com/Senior3514/AngelClaw.git /root/AngelClaw
cd /root/AngelClaw/ops
docker compose up -d --build
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
| `LLM_ENABLED` | `false` | Enable LLM proxy |
| `LLM_MODEL` | `llama3` | Ollama model name |

### After Install

```bash
# Check status
systemctl status angelclaw

# Follow logs
journalctl -u angelclaw -f

# Open dashboard
curl http://127.0.0.1:8500/ui

# Chat with AngelClaw
curl -X POST http://127.0.0.1:8500/api/v1/angelclaw/chat \
  -H 'Content-Type: application/json' \
  -d '{"tenantId":"default","prompt":"Scan the system"}'

# CLI status check
./ops/cli/angelclawctl status
```

---

## Windows Agent

The Windows installer deploys **ANGELNODE only** — it connects to your
AngelClaw Cloud running on a Linux VPS.

### Quick Install

PowerShell (as Administrator):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
git clone https://github.com/Senior3514/AngelClaw.git C:\AngelClaw
C:\AngelClaw\ops\install\install_angelclaw_windows.ps1 -CloudUrl "http://YOUR-VPS-IP:8500"
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-CloudUrl` | `http://your-cloud-server:8500` | Your VPS Cloud API URL |
| `-TenantId` | `default` | Tenant identifier |
| `-InstallDir` | `C:\AngelClaw` | Install directory |

### Example (VPS at 168.231.110.18)

```powershell
C:\AngelClaw\ops\install\install_angelclaw_windows.ps1 -CloudUrl http://168.231.110.18:8500
```

### Verify

```powershell
curl http://127.0.0.1:8400/status
```

---

## Remote UI Access (Browser / Tablet)

AngelClaw Cloud serves a full web dashboard at `/ui`.

### Option 1: SSH Tunnel (Recommended)

Most secure — no auth bypass needed:

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

### Option 3: Direct Access (Development only)

Start with public binding (NOT recommended for production):

```bash
ANGELCLAW_BIND_HOST=0.0.0.0 uvicorn cloud.api.server:app --host 0.0.0.0 --port 8500
```

Then access `http://YOUR-VPS-IP:8500/ui`.

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

When auth is enabled (default), the system creates a default admin account:

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

## Architecture

```
                    +-------------------+
                    |   Browser / CLI   |
                    +--------+----------+
                             |
                    +--------v----------+
                    |  AngelClaw Cloud  |  :8500
                    |  (FastAPI + DB)   |
                    |  - AGI Brain      |
                    |  - Daemon         |
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
```
