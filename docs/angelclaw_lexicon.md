# AngelClaw V2.0.0 Lexicon

> Canonical terminology reference for AngelClaw AGI Guardian.
> All user-facing output, documentation, and UI should use these terms.

---

## Core Entities

| AngelClaw Name    | Technical Equivalent       | Description                                      |
|-------------------|----------------------------|--------------------------------------------------|
| **Seraph**        | Main Guardian Orchestrator | The central intelligence — coordinates the Legion |
| **Angel Legion**  | Sub-Agent Swarm            | The collective of all guardian sub-agents         |
| **Feather**       | Threat Indicator           | A single detected threat signal                  |
| **Quill**         | Response Action            | A remediation or hardening step                  |
| **Codex**         | Incident Record            | A tracked security incident                      |
| **Parchment**     | Audit Report               | Compliance or change audit output                |
| **Halo**          | Security Perimeter         | The protected boundary around managed systems    |
| **Nimbus**        | Event Stream               | The flow of telemetry events from agents         |

---

## The Angel Legion (Sub-Agents)

| Agent Name          | Code Name     | AgentType   | Role                                  |
|---------------------|---------------|-------------|---------------------------------------|
| **Vigil**           | Vigil         | sentinel    | Original pattern/anomaly/correlation  |
| **Net Warden**      | Net Warden    | network     | Network exposure and connection watch |
| **Vault Keeper**    | Vault Keeper  | secrets     | Secret/credential monitoring          |
| **Tool Smith**      | Tool Smith    | toolchain   | AI tool and supply chain integrity    |
| **Drift Watcher**   | Drift Watcher | behavior    | Behavioral baseline and deviation     |
| **Chronicle**       | Chronicle     | timeline    | Temporal correlation and sequencing   |
| **Glass Eye**       | Glass Eye     | browser     | Browser extension event analysis      |
| **Iron Wing**       | Iron Wing     | response    | Response/remediation executor         |
| **Deep Quill**      | Deep Quill    | forensic    | Forensic investigation                |
| **Scroll Keeper**   | Scroll Keeper | audit       | Compliance and change auditing        |

---

## Serenity Scale (Risk Levels)

The Serenity Scale maps AngelClaw-themed risk levels to traditional severity.
Higher serenity = lower risk. Used in all user-facing output.

| Serenity Level  | Traditional | Numeric | Color   | Description                       |
|-----------------|-------------|---------|---------|-----------------------------------|
| **Serene**      | info        | 0       | #2ecc71 | All clear — no threats detected   |
| **Whisper**     | low         | 1       | #3498db | Minor signals — worth noting      |
| **Murmur**      | medium      | 2       | #f39c12 | Elevated activity — watch closely |
| **Disturbed**   | high        | 3       | #e74c3c | Active threat — action needed     |
| **Storm**       | critical    | 4       | #8e44ad | Critical emergency — immediate    |

---

## Scan Types

| Name              | Scope                                                    |
|-------------------|----------------------------------------------------------|
| **Halo Sweep**    | Full system scan — all sentinels fire simultaneously     |
| **Wing Scan**     | Targeted scan — single sentinel domain (network, etc.)   |
| **Pulse Check**   | Quick health/connectivity check of all agents            |
| **Deep Dive**     | Forensic-grade investigation on a specific agent/event   |

---

## Report Types

| Name                  | Content                                              |
|-----------------------|------------------------------------------------------|
| **Dome Shield Report**| Full multi-sentinel threat assessment                |
| **Guardian Scroll**   | Periodic summary report (hourly/daily heartbeat)     |
| **Incident Codex**    | Single incident full report with forensics           |
| **Audit Parchment**   | Compliance and change audit report                   |

---

## Autonomy Modes

| Mode              | Behavior                                                 |
|-------------------|----------------------------------------------------------|
| **Observe**       | Detect and log only — no auto-response                   |
| **Suggest**       | Detect, create incidents, propose actions — await human   |
| **Auto-Apply**    | Detect and execute auto-respond playbooks immediately    |

---

## Internal Conventions

- **Serenity** is a view layer — stored internally as traditional severity (`info`, `low`, `medium`, `high`, `critical`)
- **Feathers** are `ThreatIndicator` objects from the guardian models
- **The Nimbus** refers to the event ingestion stream (`/api/v1/events/batch`)
- When displaying risk, always show both: e.g. "Disturbed (high)"
- The **Seraph** identity is used in the brain's system prompt and chat responses
