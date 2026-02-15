# ANGELGRID Glossary

| Term | Definition |
|------|-----------|
| **ANGELGRID** | The Autonomous AI Defense Fabric — a security suite that protects AI agents and infrastructure while enabling free AI adoption. Guardian angel, not gatekeeper. |
| **ANGELNODE** | A lightweight protection agent that runs on an endpoint/server/AI-host. Evaluates actions locally, allows most operations, and only blocks genuinely dangerous ones. |
| **ANGELGRID Cloud** | The centralized SaaS backend for policy management, event correlation, and multi-tenant operations. |
| **AI Shield** | The ANGELNODE subsystem that mediates AI agent tool calls (OpenClaw, MoltBot, Claude Code, etc.). Designed to let AI work freely while catching real threats. |
| **PolicySet** | A versioned collection of PolicyRules loaded by an ANGELNODE. |
| **PolicyRule** | A single rule that matches Events and produces allow/block/alert/audit decisions. |
| **Event** | The atomic unit of telemetry — any security-relevant action observed by ANGELNODE. |
| **Incident** | A correlated group of Events representing a confirmed or suspected security issue. |
| **Decision** | The output of the policy engine: action + reason + matched rule. |
| **Sensor** | A future ANGELNODE module that monitors process/file/network activity. |
| **LLM Proxy** | Optional component that routes LLM requests (Ollama, Claude, OpenAI) through ANGELGRID with safety guardrails. Model-agnostic by design. |
| **Guardian Angel** | Our design philosophy: ANGELGRID protects quietly in the background. Most actions pass through — only genuinely dangerous operations are blocked. |
| **Fail-Closed** | Design principle: if the policy engine is unreachable, block the action. Safety net of last resort. |
| **Zero Trust** | No implicit trust for any actor — every action is evaluated against policy. But "zero trust" means "verify everything", not "block everything". |
