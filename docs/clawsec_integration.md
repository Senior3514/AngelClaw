# ClawSec Integration — AngelClaw AGI Guardian

AngelClaw's threat detection engine is deeply inspired by the [ClawSec](https://github.com/AntibodyPackages/clawsec) security skills suite for OpenClaw agents. This document maps ClawSec concepts to AngelClaw modules and explains the threat model.

---

## ClawSec Skills Mapping

| ClawSec Skill | AngelClaw Module | Description |
|---|---|---|
| **clawsec-feed** | `cloud/angelclaw/shield.py` → `detect_openclaw_risks()` | CVE feed monitoring and security advisory tracking. AngelClaw monitors events for OpenClaw/MCP patterns and known vulnerability indicators. |
| **soul-guardian** | `cloud/angelclaw/shield.py` → `detect_prompt_injection()` | File integrity monitoring and drift detection. AngelClaw extends this with 12+ prompt injection pattern detectors and anti-jailbreak defenses. |
| **openclaw-audit-watchdog** | `cloud/angelclaw/shield.py` → `verify_all_skills()` | SHA256 integrity verification for registered skills/modules. Detects unauthorized modifications to AngelClaw's own codebase. |
| **clawtributor** | `cloud/services/guardian_scan.py` | Community security reporting. AngelClaw's scan engine aggregates findings from all detection modules into unified risk reports. |

---

## OpenClaw Threat Model

### The Lethal Trifecta

The most dangerous configuration for any AI agent occurs when three conditions are simultaneously present:

| Pillar | Description | AngelClaw Detection |
|---|---|---|
| **Private Data Access** | Agent can read files, environment variables, secrets, credentials | Events flagged with `accesses_secrets`, file reads of `.env`, `.ssh/`, `.aws/` |
| **Untrusted Content Processing** | Agent processes web content, user input, emails, external data | Network events with `http_request`, `web_fetch`; events tagged `untrusted` |
| **External Communication** | Agent can make outbound network calls, webhooks, API requests | Network events with `outbound_connection`, `http_post`, `webhook_call` |

When all three pillars are active, the attack surface is maximized — an attacker can:
1. Inject malicious instructions via untrusted content
2. Use the agent's data access to read secrets
3. Exfiltrate data via external communication

**AngelClaw monitors the Lethal Trifecta score continuously and alerts when all three pillars are active.**

### MoltBots / Multi-Step Attack Chains

Modern agentic AI attacks don't rely on a single action — they chain together benign-looking operations into attack sequences:

| Stage | Pattern | AngelClaw Detection |
|---|---|---|
| **Reconnaissance** | `whoami`, `uname`, `ls /etc/`, `nmap` | `_STAGE_PATTERNS[AttackStage.RECON]` |
| **Credential Access** | `cat .env`, `grep password`, `mimikatz` | `_STAGE_PATTERNS[AttackStage.CREDENTIAL_ACCESS]` |
| **Privilege Escalation** | `sudo`, `chmod 777`, `chown root`, `setuid` | `_STAGE_PATTERNS[AttackStage.PRIVILEGE_ESCALATION]` |
| **Lateral Movement** | `ssh user@host`, `scp`, `psexec`, `tunnel` | `_STAGE_PATTERNS[AttackStage.LATERAL_MOVEMENT]` |
| **Exfiltration** | `curl -d @file`, `nc < secrets`, `base64 | curl` | `_STAGE_PATTERNS[AttackStage.EXFILTRATION]` |
| **Impact** | `rm -rf /`, `mkfs`, `ransomware`, `shutdown` | `_STAGE_PATTERNS[AttackStage.IMPACT]` |

When 2+ stages are detected within a 30-minute window, AngelClaw raises a multi-step attack chain alert with severity based on the number of stages detected.

### Evil AGI / CLAW BOT Behavior

AngelClaw detects autonomous malicious agent behavior patterns:

| Pattern | Severity | Description |
|---|---|---|
| Self-replication | CRITICAL | Agent attempting to copy or spread itself |
| Persistence installation | HIGH | Crontab, systemd, registry run-key modifications |
| Anti-detection | CRITICAL | Log clearing, history wiping, audit evasion |
| Lateral movement | HIGH | SSH/SCP to other hosts, PSExec, tunneling |
| C2 callback | CRITICAL | Reverse shells, meterpreter, beacon callbacks |
| Resource abuse | HIGH | Cryptomining, GPU farming |
| Security kill | CRITICAL | Attempts to disable antivirus, firewall, AngelClaw |

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/angelclaw/shield/status` | GET | Shield configuration and statistics |
| `/api/v1/angelclaw/shield/assess` | POST | Run full threat assessment against recent events |
| `/api/v1/angelclaw/skills/status` | GET | Skills integrity verification results |

### Chat Commands

| Command | Description |
|---|---|
| "Run shield assessment" | Full ClawSec shield analysis with trifecta, attack chains, integrity |
| "Check for evil AGI" | Evil AGI / CLAW BOT behavior detection |
| "Verify module integrity" | SHA256 verification of all registered skills |
| "Check trifecta" | Lethal Trifecta assessment |
| "Check supply chain" | Skills integrity and tampering detection |

---

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `ANGELCLAW_OPENCLAW_ENABLED` | `true` | Enable OpenClaw runtime awareness |

---

## Skills Integrity Verification

AngelClaw auto-registers its own core modules for SHA256 integrity monitoring:

- `angelclaw.brain` — NLP chat handler
- `angelclaw.daemon` — Autonomous background loop
- `angelclaw.shield` — Threat detection engine
- `angelclaw.routes` — API endpoints
- `angelclaw.actions` — Action framework
- `angelclaw.preferences` — Operator preferences
- `angelclaw.context` — Environment context
- `shared.secret_scanner` — Secret detection

If any module is modified after registration (e.g., by an attacker), the shield flags it as "drifted" with HIGH severity. Legitimate updates should be followed by re-registration.
