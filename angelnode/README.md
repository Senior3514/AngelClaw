# ANGELNODE – Local Autonomous Protection Agent

ANGELNODE is a lightweight, autonomous security agent that runs on endpoints, servers,
and AI-agent hosts. It mediates all sensitive actions (shell, file, network, DB, external
APIs) through a local policy engine, enforcing zero-trust principles around AI tools
and infrastructure operations.

## Structure

- `core/` – Policy engine, evaluation API, structured logging, and agent lifecycle.
- `ai_shield/` – Adapters for AI agent frameworks (OpenClaw, MoltBot, Claude Code).
- `sensors/` – Future: process, file, network, and syscall monitors.
- `config/` – Default configuration, policy files, and category defaults.

## Running

```bash
pip install -e .
uvicorn angelnode.core.server:app --host 127.0.0.1 --port 8400
```

## API Endpoints

| Method | Path                           | Description                                      |
|--------|--------------------------------|--------------------------------------------------|
| GET    | `/health`                      | Liveness probe                                   |
| GET    | `/status`                      | Agent status, counters, policy version (token-protected) |
| POST   | `/evaluate`                    | Evaluate an event against the active PolicySet   |
| POST   | `/ai/openclaw/evaluate_tool`   | AI-agent-facing tool evaluation endpoint         |

## Default-Deny by Category

The policy engine uses **per-category default actions** when no explicit rule matches.
This is configured in `config/category_defaults.json`:

| Category  | Default Action | Rationale                              |
|-----------|---------------|----------------------------------------|
| ai_tool   | **BLOCK**     | AI tool calls require explicit allow   |
| shell     | **BLOCK**     | Shell execution is high risk           |
| file      | **BLOCK**     | File operations need explicit policy   |
| network   | **BLOCK**     | Network access must be allowlisted     |
| db        | **BLOCK**     | Database access is sensitive           |
| auth      | **BLOCK**     | Auth changes require policy coverage   |
| config    | ALERT         | Config changes are logged with alert   |
| system    | AUDIT         | OS events are logged for review        |
| logging   | ALLOW         | Logging is inherently low risk         |
| metric    | ALLOW         | Metrics collection is low risk         |

If a category is **not listed** in the defaults file, the ultimate fallback
is **BLOCK** (fail-closed).

To override, edit `config/category_defaults.json` or set the
`ANGELNODE_CATEGORY_DEFAULTS_FILE` environment variable to point to a custom file.

## Cloud Sync

When `ANGELGRID_CLOUD_URL` is set, ANGELNODE automatically:

1. **Registers** with the Cloud on startup (`POST /api/v1/agents/register`),
   receiving its Cloud-assigned `agent_id` and initial PolicySet.
2. **Polls** for policy updates every `ANGELGRID_SYNC_INTERVAL` seconds
   (`GET /api/v1/policies/current?agentId=...`).
3. **Hot-reloads** the engine if the policy version has changed.
4. **Updates** `policy_version` and `last_policy_sync` in the `/status` endpoint.
5. **Logs** every sync attempt (success or failure) to the JSONL decision log
   with `record_type: "cloud_sync"`.

If the Cloud is unreachable, the agent continues enforcing its last-known
policy — sync failures are logged but never stop policy enforcement (fail-closed).

Without `ANGELGRID_CLOUD_URL` set, the agent runs in **standalone mode** using
only the local policy file.

## Secret & Password Protection

AngelClaw aggressively protects secrets across every layer. The guardian angel
philosophy applies: AI agents can do anything they want — we just make sure
secrets never leak.

### What counts as a secret?

| Category | Examples |
|----------|----------|
| API keys | `AKIA*`, `ghp_*`, `sk-*`, `sk-ant-*`, `sk_test_*` |
| Tokens | JWTs (`eyJ...`), bearer tokens, Slack tokens (`xox*-*`) |
| Passwords | Any `password=`, `passwd=`, `pwd=` assignment |
| SSH keys | `-----BEGIN * PRIVATE KEY-----` |
| Cloud creds | AWS credentials, kube config, Docker config |
| Connection strings | `postgres://user:pass@host`, `redis://...` |
| Secret files | `.env`, `.aws/credentials`, `secrets.yml`, `*.pem`, `*.key` |

### How protection works

1. **AI Shield adapter** (`ai_shield/openclaw_adapter.py`):
   - Scans all tool-call arguments for secret patterns and sensitive paths
   - If found: `accesses_secrets=True` → triggers `block-ai-tool-secrets-access` rule
   - Severity escalated to CRITICAL for any secret-touching operation
   - Arguments are **redacted** before logging (secrets never written to logs)

2. **Policy rules** (`config/default_policy.json`):
   - `block-file-read-ssh-keys` — blocks reads of SSH private keys
   - `block-file-read-credentials` — blocks reads of `.env`, AWS creds, kube config, etc.
   - `block-ai-tool-secrets-access` — blocks any AI tool flagged with `accesses_secrets`

3. **Cloud AI Assistant** + **LLM Proxy**:
   - All event data is redacted before being returned to users or sent to LLMs
   - The LLM system prompt strictly forbids outputting secrets
   - Even if logs contain raw secrets, AngelClaw will redact them in responses

### Example: secret detection in action

```bash
# AI agent tries to read .env file → BLOCKED
curl -X POST http://127.0.0.1:8400/ai/openclaw/evaluate_tool \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "read_file", "arguments": {"path": "/app/.env"}}'
# → {"allowed": false, "action": "block", "reason": "Block AI tool calls that attempt to access secrets"}

# AI agent tries to pass an API key as argument → BLOCKED
curl -X POST http://127.0.0.1:8400/ai/openclaw/evaluate_tool \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "http_request", "arguments": {"api_key": "sk-1234567890abcdef"}}'
# → {"allowed": false, "action": "block", "reason": "Block AI tool calls that attempt to access secrets"}
```

## /status Endpoint Security

The `/status` endpoint returns read-only operational data (agent ID, policy
version, sync timestamp, evaluation counters). It does **not** expose secrets,
tokens, or policy rule content.

- **Default:** Open on loopback (127.0.0.1) only.
- **Token protection:** Set `ANGELNODE_STATUS_TOKEN` environment variable.
  When set, requests must include `X-ANGELNODE-TOKEN: <token>` header.

## Environment Variables

| Variable                           | Description                                    | Default                          |
|------------------------------------|------------------------------------------------|----------------------------------|
| `ANGELNODE_POLICY_FILE`            | Path to the PolicySet JSON file                | `config/default_policy.json`     |
| `ANGELNODE_CATEGORY_DEFAULTS_FILE` | Path to category defaults JSON                 | `config/category_defaults.json`  |
| `ANGELNODE_LOG_FILE`               | Path for structured decision log (JSONL)       | `logs/decisions.jsonl`           |
| `ANGELNODE_AGENT_ID`               | Unique identifier for this agent               | `local-dev-agent`                |
| `ANGELNODE_STATUS_TOKEN`           | Bearer token for `/status` (optional)          | *(unset — open on loopback)*     |
| `ANGELNODE_EVALUATE_URL`           | URL of the local `/evaluate` endpoint          | `http://127.0.0.1:8400/evaluate` |
| `ANGELGRID_CLOUD_URL`             | Cloud backend URL (enables sync when set)      | *(unset — standalone mode)*      |
| `ANGELGRID_TENANT_ID`             | Tenant identifier for multi-tenant Cloud       | `default`                        |
| `ANGELGRID_SYNC_INTERVAL`         | Policy poll interval in seconds                | `60`                             |
| `ANGELNODE_AGENT_TYPE`             | Agent type for registration                    | `server`                         |
| `ANGELNODE_VERSION`                | Agent version reported to Cloud                | `0.4.0`                          |
| `ANGELNODE_TAGS`                   | Comma-separated tags for agent registration    | *(empty)*                        |
