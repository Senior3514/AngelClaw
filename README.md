# ANGELGRID – Autonomous AI Defense Fabric

ANGELGRID is a security suite designed to protect AI agents and underlying
IT/cloud infrastructure from cyber threats including prompt injection, data
exfiltration, misconfiguration, and malicious behavior.

The suite is autonomous, proactive, and continuously learning. It operates 24/7
and enforces zero-trust policy around all AI tools and infrastructure operations.

## Repository Structure

```
angelgrid/
├── angelnode/           # Local autonomous protection agent
│   ├── core/            #   Policy engine, evaluation API, structured logging
│   ├── ai_shield/       #   AI agent adapters (OpenClaw, MoltBot, Claude Code)
│   ├── sensors/         #   Future: process/file/network monitors
│   └── config/          #   Default policies and configuration
├── cloud/               # SaaS backend (ANGELGRID Cloud)
│   ├── api/             #   FastAPI REST endpoints
│   ├── db/              #   SQLAlchemy ORM models and session management
│   └── services/        #   Business logic (policy compilation, incidents)
├── agentless/           # Cloud connectors and legacy scanners
│   ├── connectors/      #   AWS/Azure/GCP API connectors
│   └── scanners/        #   Misconfiguration scanners
├── shared/              # Shared models, security helpers, config schemas
│   ├── models/          #   Pydantic data models (Event, Policy, Incident, etc.)
│   ├── security/        #   Cryptographic helpers and input sanitization
│   └── config/          #   Configuration schemas
├── ops/                 # Deployment and integrations
│   ├── docker/          #   Dockerfiles and compose configurations
│   ├── wazuh/           #   Wazuh SIEM integration configs and rules
│   └── infra/           #   Future: Terraform/Pulumi modules
└── docs/                # Architecture, threat model, concepts
```

## Tech Stack

| Component       | Technology                          |
|-----------------|-------------------------------------|
| Language        | Python 3.11+                        |
| Data Models     | Pydantic v2                         |
| HTTP Framework  | FastAPI + Uvicorn                   |
| Database        | SQLAlchemy 2.0 + SQLite (dev) / PostgreSQL (prod) |
| SIEM            | Wazuh (via Filebeat)                |
| Containers      | Docker + docker-compose             |

## Quick Start

```bash
# Install dependencies
pip install -e ".[dev,cloud]"

# Run the ANGELNODE agent (localhost:8400)
uvicorn angelnode.core.server:app --host 127.0.0.1 --port 8400

# Run ANGELGRID Cloud (localhost:8500)
uvicorn cloud.api.server:app --host 127.0.0.1 --port 8500
```

## Core Concepts

- **ANGELNODE** – Lightweight agent that evaluates every action against policy locally.
- **AI Shield** – Zero-trust mediator for AI agent tool calls.
- **PolicySet** – Versioned collection of rules distributed to agents.
- **Fail-Closed** – If the engine is unreachable, actions are blocked by default.

See [docs/concepts/glossary.md](docs/concepts/glossary.md) for the full glossary.

## License

See [LICENSE](LICENSE).
