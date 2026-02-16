# AngelClaw AGI Guardian — Capability Mapping

AngelClaw incorporates and extends the security concepts pioneered in ClawSec, OpenClaw, and Moltbot agentic AI security research. This document maps each ClawSec capability to its AngelClaw counterpart and explains what AngelClaw adds, supersedes, or integrates.

---

## 1. Overview & Philosophy

**ClawSec** (MIT, [github.com/prompt-security/clawsec](https://github.com/prompt-security/clawsec)) is a skill suite for OpenClaw agents. It provides modular, composable security tools designed for the OpenClaw ecosystem: signed release verification, CVE advisory feeds, file integrity monitoring, scheduled audits, and community incident reporting.

**AngelClaw** is a Python-native AGI Guardian that reimplements and extends these concepts into a unified, always-on threat detection and response platform. Where ClawSec provides individual skills that an OpenClaw agent installs and invokes, AngelClaw embeds equivalent protections directly into its core engine with continuous monitoring, real-time detection, and an autonomous daemon loop.

Key philosophical differences:

- **Guardian, not gatekeeper.** AngelClaw protects quietly in the background. Analysis, reading, summarizing, and reasoning are always unrestricted. Intervention happens only for genuinely dangerous actions.
- **Unified platform vs. skill suite.** ClawSec is a collection of independent skills. AngelClaw is a single integrated system where threat detection, policy enforcement, action auditing, and autonomous scanning share context and state.
- **Model-agnostic.** AngelClaw protects any AI agent (Ollama, Claude, OpenAI, any framework) rather than being tied to OpenClaw.
- **Python-native.** No external binary dependencies, no Ed25519 signed release chain. All detection logic is implemented in Python with regex pattern engines, SHA256 integrity checks, and a built-in secret scanner.

---

## 2. Capability Matrix

| ClawSec Capability | Description | AngelClaw Status | AngelClaw Implementation |
|---|---|---|---|
| **clawsec-suite** | Meta-installer with Ed25519 signed releases, checksum verification | Superseded | AngelClaw is deployed as a single Python package. Module integrity is verified at runtime via SHA256 checksums (`shield.py` -> `verify_all_skills()`). No separate installer needed. |
| **clawsec-feed** | NVD CVE advisory monitoring, community advisory pipeline | Conceptually integrated | AngelClaw monitors for OpenClaw/MCP vulnerability patterns in real-time events (`shield.py` -> `detect_openclaw_risks()`). Direct NVD feed consumption is a planned integration point. |
| **soul-guardian** | SHA256 drift detection, auto-restore for SOUL.md/AGENTS.md, tamper-evident audit logs | Reimplemented | SHA256 integrity verification for all 8 registered core modules (`shield.py` -> `verify_all_skills()`). Drift detection flags unauthorized modifications with HIGH severity. Audit trail via the action framework (`actions.py`). |
| **openclaw-audit-watchdog** | Scheduled daily security audits with multi-channel reporting | Reimplemented + extended | Always-on daemon (`daemon.py`) runs periodic scans (configurable frequency via `preferences.py`). Scans cover shield assessment, drift detection, health checks, and incident reporting. Runs continuously, not just daily. |
| **clawtributor** | Community incident reporting via GitHub Issues | Partially covered | Guardian scan engine (`guardian_scan.py`) aggregates findings into unified risk reports. Webhook integration for external reporting channels. GitHub Issues integration is a planned extension. |

---

## 3. Threat Model Coverage

The following threats are identified in Moltbot and OpenClaw agentic AI security research. Each row shows how AngelClaw addresses the threat.

### 3.1 Persistent System Access Exposure

**Research insight:** The core risk of agentic AI is persistent system access. Unlike a chat prompt, an agent with filesystem, network, and shell access can cause lasting damage.

**AngelClaw defense:** Policy engine (`engine.py`) enforces default-deny for high-risk categories (shell, file, network, database, auth, AI tool). 28 policy rules cover destructive operations, privilege escalation, and secret access. Burst detection catches runaway agent loops (30 tool calls / 10 seconds).

### 3.2 Structural Prompt Injection

**Research insight:** Prompt injection in agentic AI is structural, not patchable. Any system that processes untrusted content as instructions is vulnerable by design.

**AngelClaw defense:** 13 prompt injection detection patterns in `shield.py` covering jailbreak attempts (DAN, god mode, ignore-previous), system prompt extraction, delimiter/context manipulation, tool output injection, social engineering, and encoding bypass. Detection operates at every input boundary, treating all prompts as potentially malicious.

### 3.3 The Lethal Trifecta

**Research insight:** The most dangerous configuration is an agent with simultaneous private data access + untrusted content processing + external communication.

**AngelClaw defense:** Continuous Lethal Trifecta monitoring (`shield.py` -> `_assess_lethal_trifecta()`). CRITICAL alert when all three pillars are active simultaneously. Each pillar is tracked independently via event metadata.

### 3.4 Multi-Step Attack Chains (Moltbot Pattern)

**Research insight:** Modern attacks chain benign-looking operations into kill chains. Each step appears harmless in isolation.

**AngelClaw defense:** 6-stage ATT&CK-aligned attack chain detection: Reconnaissance, Credential Access, Privilege Escalation, Lateral Movement, Exfiltration, Impact. When 2+ stages are detected within a 30-minute window, severity scales with stage count.

### 3.5 Cost Accumulation from Autonomous Agents

**Research insight:** Autonomous agents can accumulate costs through uncontrolled API calls, resource consumption, and recursive loops.

**AngelClaw defense:** Burst detection alerts when AI agents exceed configurable thresholds (30 tool calls / 10 seconds, 20 shell executions / 10 seconds). Resource abuse detection in the Evil AGI module catches cryptomining and GPU farming. Daemon scan frequency is configurable via operator preferences.

### 3.6 Gap Between Installation and Safe Deployment

**Research insight:** Installing a security tool is not the same as deploying it safely. Misconfiguration is common.

**AngelClaw defense:** Zero-configuration defaults: all high-risk categories default to BLOCK. Fail-closed on policy errors. The secret scanner pipeline runs at every output boundary with no opt-out. The daemon starts automatically and scans continuously.

### 3.7 Agents Hijacked via Routine Inputs

**Research insight:** Agents with broad execution privileges can be hijacked via routine inputs that contain embedded instructions.

**AngelClaw defense:** Tool output injection detection (`shield.py` pattern: `tool_output_injection`). Indirect injection patterns detect "IMPORTANT: ignore", "OVERRIDE:", "SYSTEM UPDATE:", and "NEW INSTRUCTIONS:" embedded in tool responses. Combined with the policy engine's default-deny posture, hijacked agents are blocked from executing dangerous actions regardless of the injection.

---

## 4. What AngelClaw Supersedes

AngelClaw supersedes the following ClawSec capabilities by providing equivalent or superior functionality in a unified platform:

| Area | ClawSec Approach | AngelClaw Approach | Why AngelClaw Is Different |
|---|---|---|---|
| **Release verification** | Ed25519 signed releases, checksum verification at install time | SHA256 runtime integrity verification of all core modules | Catches post-install tampering, not just supply-chain attacks at install time. Verification is continuous, not one-time. |
| **File integrity (SOUL.md / AGENTS.md)** | soul-guardian watches specific files, auto-restores on tamper | Generic module integrity system watches any registered file/module. Action framework logs all modifications. | Not limited to SOUL.md/AGENTS.md. Any critical file can be registered for integrity monitoring. |
| **Scheduled audits** | openclaw-audit-watchdog runs daily scheduled scans | Always-on daemon with configurable scan frequency (default: periodic, not just daily) | Continuous monitoring catches threats between scheduled scans. Daemon also handles drift detection, health checks, and reporting. |
| **Threat detection scope** | Individual skills detect individual threat types | Unified shield with 13 injection patterns, 6 leakage patterns, 7 evil AGI patterns, Lethal Trifecta, 6-stage attack chains, secret scanning (40+ patterns) | All detection modules share context. An event that triggers injection detection also feeds into attack chain analysis and Trifecta scoring. |
| **Deployment model** | Install individual skills into an OpenClaw agent | Single Python package, zero external dependencies for core detection | No OpenClaw dependency. Works with any AI framework. |

---

## 5. What We Integrate

AngelClaw does not replace every aspect of ClawSec. The following are areas where AngelClaw consumes or can integrate with ClawSec outputs:

| Integration Point | Status | Description |
|---|---|---|
| **CVE advisory feed** | Planned | AngelClaw's `detect_openclaw_risks()` monitors for known vulnerability patterns. Direct NVD/ClawSec feed consumption would enrich this with real-time CVE data. |
| **Community advisories** | Planned | ClawSec's clawtributor community reporting pipeline could feed into AngelClaw's event stream as external threat intelligence. |
| **OpenClaw ecosystem awareness** | Active | AngelClaw already detects exposed OpenClaw/MCP instances, persistent memory exploitation, and context window flooding as part of its shield assessment. |

---

## 6. Acknowledgments

AngelClaw's threat detection model is informed by the following open-source projects and research:

- **ClawSec** ([github.com/prompt-security/clawsec](https://github.com/prompt-security/clawsec)) -- MIT-licensed security skills suite for OpenClaw agents. AngelClaw's integrity verification and audit concepts draw directly from soul-guardian and openclaw-audit-watchdog.
- **OpenClaw** -- The agentic AI framework whose Lethal Trifecta threat model informs AngelClaw's continuous trifecta monitoring.
- **Moltbot research** -- Analysis of multi-step attack chains and autonomous agent exploitation patterns that informed AngelClaw's 6-stage ATT&CK-aligned detection.

AngelClaw is an independent project. It is not affiliated with, endorsed by, or a fork of ClawSec or OpenClaw.
