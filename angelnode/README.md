# ANGELNODE – Local Autonomous Protection Agent

ANGELNODE is a lightweight, autonomous security agent that runs on endpoints, servers,
and AI-agent hosts. It mediates all sensitive actions (shell, file, network, DB, external
APIs) through a local policy engine, enforcing zero-trust principles around AI tools
and infrastructure operations.

## Structure

- `core/` – Policy engine, evaluation API, structured logging, and agent lifecycle.
- `ai_shield/` – Adapters for AI agent frameworks (OpenClaw, MoltBot, Claude Code).
- `sensors/` – Future: process, file, network, and syscall monitors.
- `config/` – Default configuration and sample policy files.

## Running

```bash
cd angelnode
pip install -e .
uvicorn core.server:app --host 127.0.0.1 --port 8400
```

The agent exposes:
- `POST /evaluate` – Evaluate an event against the loaded PolicySet.
- `POST /ai/openclaw/evaluate_tool` – AI-agent-facing tool evaluation endpoint.
