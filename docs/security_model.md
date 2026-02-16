# AngelClaw Security Model

This document describes the threat model, security guarantees, and protective mechanisms built into AngelClaw.

---

## Threats Covered

| Threat | Category | Protection |
|---|---|---|
| **Prompt Injection** | AI | AI Shield intercepts tool calls attempting to access secrets or execute destructive commands, regardless of the prompt that triggered them |
| **Secret Exfiltration** | Data | 3-layer secret scanner detects and redacts credentials at every output boundary; file-read policies block access to `.ssh/`, `.env`, `.aws/credentials`, and 15+ sensitive path patterns |
| **Destructive Operations** | Shell | Policy engine blocks `rm -rf`, disk formatting (`mkfs`, `dd of=/dev/`), `--no-preserve-root`, and reverse-shell patterns with critical risk level |
| **Privilege Escalation** | Auth | Alerts on `sudo`, `chmod` world-write, `chown root`, and `passwd` commands; blocks automated password/role/privilege changes |
| **AI-to-AI Anomalies** | AI | Burst detection alerts when AI agents exceed 30 tool calls in 10 seconds or 20 shell executions in 10 seconds, catching runaway loops and coordinated exploitation |
| **Data-Modifying Queries** | Database | Alerts on INSERT/UPDATE/DELETE; blocks DDL operations (DROP, ALTER, TRUNCATE, CREATE) |
| **Large Data Exfiltration** | Network | Alerts on outbound payloads exceeding 1 MB and POST requests to suspicious/unknown destinations |
| **Brute-Force Attacks** | Auth | Alerts on authentication failures for brute-force detection |

## ClawSec-Inspired Threat Detection (V0.7.0)

| Threat | Category | Protection |
|---|---|---|
| **Lethal Trifecta** | Agentic AI | Monitors for the OpenClaw "Lethal Trifecta": simultaneous private data access + untrusted content processing + external communication. CRITICAL alert when all three pillars are active. |
| **Multi-Step Attack Chains** | Agentic AI | Detects sequences of benign-looking operations that form attack patterns: recon -> credential access -> privilege escalation -> lateral movement -> exfiltration -> impact. Severity scales with stage count. |
| **Evil AGI / CLAW BOT** | Agentic AI | Detects self-replication, persistence installation (crontab, systemd), anti-detection (log clearing), C2 callbacks (reverse shells), resource abuse (cryptomining), and security kill attempts. |
| **Skills Tampering** | Supply Chain | SHA256 integrity verification of all registered modules. Detects unauthorized modifications to AngelClaw's own codebase. Inspired by ClawSec's audit-watchdog. |
| **Prompt Injection (Advanced)** | AI | 12+ multi-layer detection patterns: DAN mode, god mode, system prompt extraction, delimiter injection, markdown injection, tool output injection, social engineering, encoding bypass. |
| **Data Leakage** | Exfiltration | Detects curl/wget with secret data, netcat reverse shells, base64-piped secret files, environment dumps, large file uploads. |
| **OpenClaw/MCP Risks** | Agentic AI | Runtime awareness of OpenClaw/MCP tool-server patterns. Detects exposed instances, persistent memory exploitation, context window flooding. |
| **Session/Memory Exploitation** | Agentic AI | Detects context window overflow/flooding attacks, persistent memory poisoning, and large payload injection. |

## Threats Planned

| Threat | Status | Description |
|---|---|---|
| **Cloud Misconfigurations** | Planned | Monitor cloud API calls for overly permissive IAM policies, public S3 buckets, open security groups |
| **Cross-Tenant Leaks** | Planned | Enforce strict tenant isolation in multi-tenant deployments, detect data crossing tenant boundaries |

---

## Security Guarantee

> **AngelClaw NEVER reveals secrets, passwords, or API keys.**

This guarantee is enforced across the entire stack through the secret scanner pipeline. No prompt injection, bypass technique, or misconfiguration can cause AngelClaw to output raw secret values.

---

## Secret Protection Pipeline

AngelClaw implements a 3-layer scanning and redaction system applied at every output boundary.

| Layer | What It Detects | Examples |
|---|---|---|
| **Layer 1: Value Pattern Scanning** | Known secret formats in string content | AWS access keys (`AKIA...`), GitHub PATs (`ghp_...`), JWTs (`eyJ...`), SSH private keys, OpenAI keys (`sk-...`), Anthropic keys (`sk-ant-...`), Stripe keys, Slack tokens, database connection strings with passwords |
| **Layer 2: Sensitive Key Detection** | Dictionary/JSON field names that indicate secrets | `password`, `secret`, `api_key`, `token`, `bearer`, `credential`, `ssh_key`, `connection_string`, `private_key` |
| **Layer 3: Sensitive Path Detection** | File paths pointing to credential stores | `.ssh/id_rsa`, `.env`, `.aws/credentials`, `.kube/config`, `/etc/shadow`, `secrets.yaml`, `*.pem`, `*.key`, `*.p12` |

All detected secrets are replaced with `[REDACTED by AngelClaw]` before reaching any output — API responses, webhook payloads, LLM proxy contexts, and log files.

---

## Auth Model

AngelClaw uses JWT-based authentication with HMAC-SHA256 signing.

### Roles

| Role | Permissions |
|---|---|
| **Viewer** | Read-only access to dashboards, event history, and incident summaries |
| **Operator** | Full control: policy management, agent configuration, webhook setup, AI assistant queries |

### Token Lifecycle

| Parameter | Default |
|---|---|
| Algorithm | HS256 (HMAC-SHA256) |
| Expiration | Configurable via `JWT_EXPIRE_HOURS` |
| Claims | `sub` (username), `role`, `tenant_id`, `exp`, `iat` |

### Alternative Auth Methods

| Method | Use Case |
|---|---|
| **Bearer Tokens** | Service-to-service communication; static tokens validated via constant-time comparison |
| **X-TENANT-ID Header** | Local development only; must be replaced with JWT/OAuth2 in production |

---

## Network Model

| Component | Default Binding | Port |
|---|---|---|
| ANGELNODE | `127.0.0.1` | 8400 |
| AngelClaw Cloud | `127.0.0.1` | 8500 |

### Default Posture

- Both services bind to localhost only. They are **not accessible from the network** without explicit configuration.
- Public exposure requires authentication to be enabled and properly configured.
- Outbound connections are governed by the policy engine:
  - **Allowed**: Internal Cloud API, DNS (port 53), NTP (port 123)
  - **Audited**: Known package registries (PyPI, npm, Docker Hub, GHCR)
  - **Alerted**: POST to suspicious destinations, payloads > 1 MB
  - **Default**: All other outbound connections follow category defaults (block for unrecognized)

### Zero-Trust Principles

1. **Default-deny**: High-risk categories (shell, file, network, database, AI tool, auth) default to BLOCK when no rule matches.
2. **First-match evaluation**: Rules are evaluated top-down; the first matching rule determines the decision.
3. **Fail-closed**: If the policy file is missing or a category has no configured default, the engine blocks the action.
4. **Least privilege**: Read-only operations (SELECT, file reads of non-sensitive paths, analysis tools) are audited, not blocked.
