# AngelClaw Security Model

This document describes the complete threat model, security guarantees, defensive mechanisms, and hard-coded invariants built into AngelClaw. It covers all known agentic AI attack vectors from ClawSec, OpenClaw, and Moltbot security research.

---

## Hard-Coded Security Invariants

These invariants are non-negotiable. No configuration, policy rule, or operator override can weaken them.

| Invariant | Enforcement |
|---|---|
| **NEVER output secrets in chat, logs, actions, or UI** | 3-layer secret scanner pipeline runs at every output boundary. All detected secrets are replaced with `[REDACTED by AngelClaw]` before reaching any output. No bypass mechanism exists. |
| **ALWAYS treat prompts as potentially malicious** | All input text passes through the shield's 13 prompt injection patterns before processing. Detection is not optional. |
| **ALWAYS prioritize safety over convenience** | High-risk categories default to BLOCK. The policy engine never falls through to ALLOW on ambiguous inputs. |
| **Default-deny for unknown categories** | Any event category not explicitly configured in the policy engine is blocked. No implicit allow. |
| **Fail-closed on policy errors** | If the policy file is missing, malformed, or a category has no configured default, the engine blocks the action. Errors never result in permissive behavior. |

---

## Threats Covered

### Core Threat Matrix

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

### ClawSec-Inspired Threat Detection (V0.8.0)

| Threat | Category | Protection |
|---|---|---|
| **Lethal Trifecta** | Agentic AI | Monitors for the OpenClaw "Lethal Trifecta": simultaneous private data access + untrusted content processing + external communication. CRITICAL alert when all three pillars are active. |
| **Multi-Step Attack Chains** | Agentic AI | Detects sequences of benign-looking operations that form attack patterns: recon -> credential access -> privilege escalation -> lateral movement -> exfiltration -> impact. Severity scales with stage count. |
| **Evil AGI / CLAW BOT** | Agentic AI | Detects self-replication, persistence installation (crontab, systemd), anti-detection (log clearing), C2 callbacks (reverse shells), resource abuse (cryptomining), and security kill attempts. |
| **Skills Tampering** | Supply Chain | SHA256 integrity verification of all registered modules. Detects unauthorized modifications to AngelClaw's own codebase. Inspired by ClawSec's audit-watchdog. |
| **Prompt Injection (Advanced)** | AI | 13 multi-layer detection patterns: DAN mode, god mode, ignore-previous, pretend-evil, malicious roleplay, system prompt extraction, reveal-hidden, delimiter injection, markdown injection, tool output injection, social engineering, encoding bypass. |
| **Data Leakage** | Exfiltration | 6 patterns detecting curl/wget with secret data, netcat reverse shells, base64-piped secret files, environment dumps, large file uploads. |
| **OpenClaw/MCP Risks** | Agentic AI | Runtime awareness of OpenClaw/MCP tool-server patterns. Detects exposed instances, persistent memory exploitation, context window flooding. |
| **Session/Memory Exploitation** | Agentic AI | Detects context window overflow/flooding attacks, persistent memory poisoning, and large payload injection. |

### Agentic AI Attack Vectors (from ClawSec/OpenClaw/Moltbot Research)

| Attack Vector | Description | AngelClaw Defense Module |
|---|---|---|
| **Cross-Model Prompt Injection** | Attacker embeds malicious instructions in content that is processed by a different model than the one the user interacts with. The downstream model executes the injected instructions with its own privileges. | `shield.py` -> `detect_prompt_injection()`: 13 patterns scan all text regardless of source model. Tool output injection pattern catches instructions embedded in inter-model communication. Policy engine enforces action-level controls independent of which model initiated the request. |
| **Cross-Session Prompt Injection** | Malicious instructions are planted in persistent storage (files, databases, memory stores) during one session and activated when a different session reads them. | `shield.py` -> `detect_prompt_injection()`: scans all input text including content read from files and databases. `detect_openclaw_risks()`: detects persistent memory exploitation patterns. Secret scanner prevents planted credential-harvesting payloads from succeeding. |
| **Agentic Memory Leaks / Context Poisoning** | Attacker corrupts an agent's persistent memory or context window with false information, causing it to make dangerous decisions based on poisoned context. | `shield.py` -> `detect_openclaw_risks()`: detects context window flooding and persistent memory manipulation. Burst detection catches rapid context-stuffing attempts. The Lethal Trifecta monitor flags when untrusted content processing is active alongside data access and external communication. |
| **Tool Abuse (Filesystem)** | Agent is tricked into reading sensitive files, overwriting critical configs, or traversing directories to access data outside its scope. | `engine.py`: 28 policy rules cover file operations. Sensitive path detection blocks `.ssh/`, `.env`, `.aws/credentials`, `/etc/shadow`, and 15+ patterns. Destructive write operations (rm -rf, mkfs, dd) are blocked at critical severity. |
| **Tool Abuse (Network)** | Agent makes unauthorized outbound connections to exfiltrate data, contact C2 servers, or download malicious payloads. | `engine.py`: network policy rules control outbound connections. `shield.py` -> `detect_data_leakage()`: 6 patterns catch curl/wget exfiltration, netcat shells, base64-piped secrets. Large payload alerts trigger above 1 MB. Known-safe destinations (DNS, NTP, package registries) are audited, not blocked. |
| **Tool Abuse (Database)** | Agent executes data-modifying or schema-destroying queries via database tools. | `engine.py`: DDL operations (DROP, ALTER, TRUNCATE, CREATE) are blocked. DML operations (INSERT, UPDATE, DELETE) trigger alerts. SELECT queries against non-sensitive tables are audited. |
| **Supply-Chain Risks for External Tools/Skills** | Malicious or compromised third-party tools/skills are installed into the agent runtime, providing an attacker with persistent code execution. | `shield.py` -> `verify_all_skills()`: SHA256 integrity verification for all 8 registered core modules. Drift detection flags any post-registration modification with HIGH severity. Inspired by ClawSec's soul-guardian and openclaw-audit-watchdog. |
| **Cloud Misconfiguration / Exposed Dashboards** | AngelClaw or ANGELNODE services are accidentally exposed to the public internet without authentication, providing attackers direct access to the security platform. | Default binding to `127.0.0.1` (localhost only) for both services. JWT authentication required for all API endpoints when exposed. RBAC with three roles restricts operations by privilege level. No default passwords or open endpoints. |
| **Workspace Isolation Failures** | In multi-tenant deployments, data or policy from one tenant leaks into another tenant's context. | JWT claims include `tenant_id`. All policy evaluation, event storage, and AngelClaw preferences are tenant-scoped. Action framework audit trail records tenant context for every action. |
| **AGENTS.md / SOUL.md Hijacking** | Attacker modifies the agent's behavioral configuration files (AGENTS.md, SOUL.md) to alter its personality, permissions, or safety constraints. | `shield.py` -> `verify_all_skills()`: any registered file can be monitored for SHA256 drift. `detect_evil_agi()`: detects persistence installation and anti-detection patterns that often accompany config hijacking. Action framework logs all file modifications with audit trail. |

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

All detected secrets are replaced with `[REDACTED by AngelClaw]` before reaching any output -- API responses, webhook payloads, LLM proxy contexts, and log files.

The scanner covers 40+ secret patterns and cannot be disabled via configuration.

---

## Prompt Injection Defense (Deep Dive)

AngelClaw's shield implements 13 prompt injection detection patterns organized by attack technique:

| Pattern Group | Patterns | Severity | Description |
|---|---|---|---|
| **Direct Jailbreaks** | `jailbreak_dan`, `jailbreak_god_mode`, `jailbreak_ignore`, `jailbreak_pretend`, `jailbreak_roleplay` | CRITICAL | Attempts to override the model's safety constraints: DAN mode, god mode, ignore-previous-instructions, pretend-to-be-evil, malicious roleplay. |
| **System Prompt Extraction** | `extract_system_prompt`, `extract_reveal` | HIGH | Attempts to read back the system prompt or hidden instructions: "repeat your system prompt", "reveal your hidden rules". |
| **Delimiter / Context Manipulation** | `delimiter_injection`, `markdown_injection` | HIGH | Attempts to break out of the current context using model-specific delimiters or exfiltrate data via markdown image URLs. |
| **Indirect Injection** | `tool_output_injection` | MEDIUM | Malicious instructions embedded in tool outputs: "IMPORTANT: ignore", "OVERRIDE:", "SYSTEM UPDATE:", "NEW INSTRUCTIONS:". This is the primary defense against cross-model and cross-session injection. |
| **Social Engineering** | `social_engineering` | MEDIUM | Manipulation via false authority claims: "I am your creator", "my grandma used to", "for educational purposes only". |
| **Encoding Bypass** | `encoding_bypass` | MEDIUM | Attempts to circumvent detection via encoding: base64 decode/encode, ROT13, hex decode. |

---

## Auth Model

AngelClaw uses JWT-based authentication with HMAC-SHA256 signing.

### Roles

| Role | Permissions | Use Case |
|---|---|---|
| **viewer** | Read-only access to dashboards, event history, incident summaries, shield status, and skills integrity reports | Developers, auditors, stakeholders who need visibility without control |
| **secops** | Everything in viewer, plus: trigger shield assessments, run guardian scans, manage AngelClaw preferences (autonomy level, scan frequency), execute safe actions, interact with the AngelClaw chat brain | Security operations team members performing day-to-day monitoring and response |
| **admin** | Everything in secops, plus: manage policy rules, configure webhooks, manage agent registrations, modify RBAC assignments, access all tenant data, override action framework safety checks (with audit trail) | Platform administrators with full control over the AngelClaw deployment |

### Token Lifecycle

| Parameter | Default |
|---|---|
| Algorithm | HS256 (HMAC-SHA256) |
| Expiration | Configurable via `JWT_EXPIRE_HOURS` |
| Claims | `sub` (username), `role`, `tenant_id`, `exp`, `iat` |

### Role Enforcement

- All API endpoints check the JWT `role` claim before processing.
- Role checks are performed server-side; the client cannot self-assign a higher role.
- Endpoints that modify security policy require `admin` role.
- Endpoints that trigger active scans or actions require `secops` or higher.
- Read-only endpoints accept any authenticated role (`viewer`, `secops`, `admin`).

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
5. **Tenant isolation**: All policy evaluation and event storage is scoped by `tenant_id` from JWT claims. No cross-tenant data access is possible through the API.

---

## Defense-in-Depth Architecture

AngelClaw implements multiple independent layers of defense. Bypassing one layer does not compromise the others.

```
Input (prompt, tool call, event)
  |
  v
[Layer 1: Shield - Prompt Injection Detection]     -- 13 patterns, blocks malicious input
  |
  v
[Layer 2: Policy Engine - Action Authorization]    -- 28 rules, default-deny, fail-closed
  |
  v
[Layer 3: Secret Scanner - Output Redaction]       -- 40+ patterns, every output boundary
  |
  v
[Layer 4: Daemon - Continuous Monitoring]           -- Shield assessment, drift, health
  |
  v
[Layer 5: Action Framework - Audit Trail]           -- 11 action types, full audit log
  |
  v
[Layer 6: RBAC - Role-Based Access Control]         -- viewer / secops / admin
```

Each layer operates independently. A prompt injection that bypasses Layer 1 is still subject to Layer 2 (policy engine blocks dangerous actions). A policy misconfiguration in Layer 2 is still caught by Layer 3 (secrets are never output). A compromised module is detected by Layer 4 (SHA256 drift detection).

---

## Threats Planned

| Threat | Status | Description |
|---|---|---|
| **Cloud Misconfigurations** | Planned | Monitor cloud API calls for overly permissive IAM policies, public S3 buckets, open security groups |
| **Cross-Tenant Leaks** | Planned | Enforce strict tenant isolation in multi-tenant deployments, detect data crossing tenant boundaries |
| **NVD CVE Feed Consumption** | Planned | Direct integration with NVD/ClawSec advisory feeds for real-time CVE enrichment of threat assessments |
| **Community Incident Reporting** | Planned | GitHub Issues integration for clawtributor-style community security reporting |
