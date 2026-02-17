# AngelClaw AGI Guardian — Secure Deployment Guide

Production deployment guide covering TLS termination, SSH tunnels, systemd
services, and the secure deployment checklist.

## Architecture Overview

```
  Tablet / Phone / Laptop
         |
         | HTTPS (port 443)
         v
  +------------------+
  | Nginx / Caddy    |   <-- TLS termination, security headers
  | (reverse proxy)  |
  +--------+---------+
           |
           | HTTP (127.0.0.1:8500)
           v
  +------------------+
  | AngelClaw Cloud  |   <-- JWT auth on all /api/v1/* routes
  | - Dashboard /ui  |
  | - REST API       |
  | - AI Brain       |
  +--------+---------+
           |
  +--------+---------+
  | ANGELNODE(s)      |   <-- Policy engine agents on protected hosts
  | :8400             |
  +-------------------+
```

---

## HTTPS with Nginx

### Install Nginx + Certbot

```bash
sudo apt update && sudo apt install -y nginx certbot python3-certbot-nginx
```

### Nginx Configuration

Create `/etc/nginx/sites-available/angelclaw`:

```nginx
server {
    listen 80;
    server_name angelclaw.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name angelclaw.example.com;

    ssl_certificate     /etc/letsencrypt/live/angelclaw.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/angelclaw.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://127.0.0.1:8500;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### Enable and Obtain Certificate

```bash
sudo ln -sf /etc/nginx/sites-available/angelclaw /etc/nginx/sites-enabled/
sudo certbot --nginx -d angelclaw.example.com
sudo systemctl reload nginx
```

---

## HTTPS with Caddy

Caddy provides automatic TLS via Let's Encrypt with minimal configuration.

### Install Caddy

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy
```

### Caddyfile

Create `/etc/caddy/Caddyfile`:

```
angelclaw.example.com {
    reverse_proxy localhost:8500
    encode gzip
    header {
        Strict-Transport-Security "max-age=31536000;"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
    }
}
```

```bash
sudo systemctl enable caddy && sudo systemctl start caddy
```

Caddy automatically obtains and renews TLS certificates.

---

## SSH Tunnel (Simplest Method)

For personal access — no certificates, no reverse proxy needed.

```bash
# Forward Cloud dashboard to local port
ssh -L 8500:127.0.0.1:8500 user@your-vps-ip
# Then open http://localhost:8500/ui

# Forward both services
ssh -L 8400:127.0.0.1:8400 -L 8500:127.0.0.1:8500 user@your-vps-ip
```

### Persistent Tunnel with autossh

```bash
sudo apt install -y autossh
autossh -M 0 -f -N -L 8500:127.0.0.1:8500 user@your-vps-ip
```

### SSH Config Shortcut

Add to `~/.ssh/config`:

```
Host angelclaw
    HostName your-vps-ip
    User root
    LocalForward 8500 127.0.0.1:8500
    LocalForward 8400 127.0.0.1:8400
    ServerAliveInterval 60
    ServerAliveCountMax 3
```

Then: `ssh angelclaw` and open `http://localhost:8500/ui`.

---

## Systemd Service

### Docker Compose Service (Recommended)

Create `/etc/systemd/system/angelclaw.service`:

```ini
[Unit]
Description=AngelClaw AGI Guardian
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/angelclaw/ops
ExecStart=/usr/bin/docker compose up -d --build
ExecStop=/usr/bin/docker compose down --timeout 30
ExecReload=/usr/bin/docker compose up -d --build
TimeoutStartSec=300
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
```

### Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable angelclaw
sudo systemctl start angelclaw
sudo systemctl status angelclaw
```

---

## Secure Deployment Checklist

### Authentication

- [ ] `ANGELCLAW_AUTH_ENABLED=true` (default)
- [ ] Set strong `ANGELCLAW_ADMIN_PASSWORD`
- [ ] Set `ANGELCLAW_JWT_SECRET` to a unique random string
- [ ] Create `secops` accounts for operators
- [ ] Use `viewer` accounts for read-only stakeholders

### Network Binding

- [ ] Bind to `127.0.0.1` (default) — never `0.0.0.0` without auth
- [ ] Use TLS termination via Nginx or Caddy for public access
- [ ] Verify: `ss -tlnp | grep -E '8400|8500'`

### Firewall

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp     # SSH
sudo ufw allow 443/tcp    # HTTPS
sudo ufw deny 8500/tcp    # Block direct Cloud access
sudo ufw deny 8400/tcp    # Block direct ANGELNODE access
sudo ufw enable
```

### Service Hardening

- [ ] Use systemd for auto-restart and boot start
- [ ] Configure log rotation (`/etc/logrotate.d/angelclaw`)
- [ ] Monitor `/health` endpoint with uptime checker
- [ ] Forward logs to SIEM (Wazuh integration built in)

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANGELCLAW_AUTH_ENABLED` | `true` | JWT authentication |
| `ANGELCLAW_ADMIN_PASSWORD` | *(none)* | Admin password |
| `ANGELCLAW_JWT_SECRET` | *(auto)* | JWT signing key |
| `ANGELCLAW_BIND_HOST` | `127.0.0.1` | API bind address |
| `ANGELCLAW_BIND_PORT` | `8500` | API port |
| `LLM_ENABLED` | `false` | Enable LLM proxy |
| `LLM_MODEL` | `llama3` | Ollama model name |

---

## Access from Any Device

| Device | Method | URL |
|--------|--------|-----|
| Linux server | Direct | `http://127.0.0.1:8500/ui` |
| macOS / Linux laptop | SSH tunnel | `ssh -L 8500:127.0.0.1:8500 user@vps` |
| Windows desktop | SSH or HTTPS | See Windows installer docs |
| Tablet / phone | HTTPS reverse proxy | `https://angelclaw.example.com/ui` |
