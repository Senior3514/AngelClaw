# ANGELGRID Glossary

| Term | Definition |
|------|-----------|
| **ANGELGRID** | The overall Autonomous AI Defense Fabric — the product suite. |
| **ANGELNODE** | A lightweight protection agent that runs on an endpoint/server/AI-host. |
| **ANGELGRID Cloud** | The centralized SaaS backend for policy management, event correlation, and multi-tenant operations. |
| **AI Shield** | The ANGELNODE subsystem that mediates AI agent tool calls (OpenClaw, MoltBot, Claude Code). |
| **PolicySet** | A versioned collection of PolicyRules loaded by an ANGELNODE. |
| **PolicyRule** | A single rule that matches Events and produces allow/block/alert/audit decisions. |
| **Event** | The atomic unit of telemetry — any security-relevant action observed by ANGELNODE. |
| **Incident** | A correlated group of Events representing a confirmed or suspected security issue. |
| **Decision** | The output of the policy engine: action + reason + matched rule. |
| **Sensor** | A future ANGELNODE module that monitors process/file/network activity. |
| **Fail-Closed** | Design principle: if the policy engine is unreachable, block the action. |
| **Zero Trust** | No implicit trust for any actor — every action is evaluated against policy. |
