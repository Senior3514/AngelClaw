# Ops – Deployment, Infrastructure & Integrations

Operational tooling for deploying, monitoring, and integrating ANGELGRID.

## Structure

- `docker/` – Dockerfiles for ANGELNODE and Cloud images.
- `docker-compose.yml` – Top-level compose file for local development (single VPS).
- `wazuh/` – Integration configs and rules for forwarding ANGELGRID events to Wazuh SIEM.
- `infra/` – Future: Terraform/Pulumi modules for cloud deployment.

## Quick Start (Local Development)

```bash
cd ops
docker compose up --build
```

This starts two services:

| Service     | Container Port | Host Binding         | Description                              |
|-------------|---------------|----------------------|------------------------------------------|
| `angelnode` | 8400          | `127.0.0.1:8400`     | Local policy agent (loopback only)       |
| `cloud`     | 8500          | *(internal only)*    | Cloud API — reachable as `http://cloud:8500` from containers |

### Verify ANGELNODE is running

```bash
curl http://127.0.0.1:8400/health
# {"status":"ok","policy_version":"..."}

curl http://127.0.0.1:8400/status
# {"agent_id":"dev-agent-01","policy_version":"...","health":"ok","counters":{...}}
```

### Expose Cloud API for debugging

Uncomment the `ports` block under the `cloud` service in `docker-compose.yml`:

```yaml
ports:
  - "127.0.0.1:8500:8500"
```

Then restart:

```bash
docker compose up --build cloud
```

## Configuration

ANGELNODE config files are bind-mounted read-only from the repo so you can
edit them without rebuilding the image:

- `angelnode/config/default_policy.json` – PolicySet rules
- `angelnode/config/category_defaults.json` – Per-category default actions (default-deny)

After editing, restart the container:

```bash
docker compose restart angelnode
```

## Volumes

| Volume            | Purpose                             |
|-------------------|-------------------------------------|
| `angelnode-logs`  | Persistent JSONL decision logs      |
| `cloud-data`      | SQLite database for the Cloud API   |

To reset all data:

```bash
docker compose down -v
```
