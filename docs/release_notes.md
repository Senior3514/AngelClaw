# ANGELGRID Release Notes

## V0.3.0 — V1 Pilot Release (2026-02-16)

**Status**: Internal testing / pilot deployment on VPS.

This is the first feature-complete release of ANGELGRID, running on a
single Ubuntu VPS with Docker Compose. It is intended for internal
testing and iteration — not production deployment.

### Major Features

**Policy Engine (ANGELNODE)**
- 28-rule bootstrap policy with first-match-wins evaluation
- Extended match syntax: `_pattern` (regex), `_in` (list), `_gt` (numeric), burst detection
- Per-category default-deny (zero-trust) with 11 categories
- Cloud sync: auto-register on startup, poll for policy updates every 60s
- Fail-closed: if engine unreachable, all actions blocked

**AI Shield**
- AI agent tool-call evaluation via `/ai/openclaw/evaluate_tool`
- Comprehensive secret detection in tool arguments (API keys, tokens, passwords, paths)
- Secret-touching operations blocked FIRST (before tool-name allowlists)
- Arguments redacted before logging — secrets never written to disk

**Secret Protection (end-to-end)**
- `shared/security/secret_scanner.py`: 17 value patterns, 7 key patterns, 16 path patterns
- Layer 1 (ANGELNODE): detect + block + redact in tool calls
- Layer 2 (Cloud AI Assistant): redact event details + explanations in responses
- Layer 3 (LLM Proxy): scrub prompt before LLM, scrub response before user
- 53 automated tests, all passing

**Cloud API (v0.3.0)**
- Agent registration + policy distribution
- Event ingestion + incident management
- AI Assistant: incident summary, policy proposals, event explanation
- LLM Proxy: Ollama integration with guardian-angel system prompt (disabled by default)
- Analytics: fleet listing, threat matrix, policy evolution, AI traffic, sessions, agent identity
- Health endpoint at `/health`

**Web Dashboard**
- Guardian Angel dashboard at `/ui`
- Fleet status table, network trust bar, active alerts feed
- Threat landscape chart, ANGELGRID AI chat interface
- Single HTML file — no build step, no Node.js

**CLI Tool**
- `angelgridctl status` — health + fleet overview
- `angelgridctl incidents` — recent events + threat matrix
- `angelgridctl test-ai-tool` — 4 automated policy checks
- `angelgridctl explain <event-id>` — decision explanation

**Infrastructure**
- Docker Compose: ANGELNODE + Cloud + Ollama (internal-only)
- systemd service: auto-start on boot, graceful shutdown
- Health watchdog: checks every 2 minutes, auto-restarts if down
- All ports bound to 127.0.0.1 (loopback only)

### Known Limitations (V1 Pilot)

- Single-VPS deployment only (no multi-node yet)
- SQLite database (switch to PostgreSQL for production)
- LLM proxy disabled by default (requires `LLM_ENABLED=true` + model pull)
- No TLS/HTTPS on API endpoints (use reverse proxy for production)
- No JWT/OAuth2 auth (using X-TENANT-ID header for dev)
- Web dashboard is a skeleton — functional but minimal styling
- Sensors (process, file, network monitors) are stubs

### What's Next

- Linux and Windows installers for easy deployment
- Multi-node agent registration with remote Cloud
- TLS + auth middleware
- Production database (PostgreSQL)
- Richer web dashboard with historical charts
- Wazuh SIEM integration testing

---

*ANGELGRID: Guardian angel, not gatekeeper.*
*We will iterate tomorrow.*
