# AngelClaw Integrations

This guide covers webhook configuration and SIEM integration for forwarding AngelClaw alerts to external systems.

---

## Webhook Configuration

AngelClaw Cloud pushes critical alerts to any HTTP(S) endpoint via the built-in webhook sink.

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANGELCLAW_WEBHOOK_URL` | Yes | Full URL of the receiving endpoint (e.g., `https://siem.example.com/webhook`) |
| `ANGELCLAW_WEBHOOK_SECRET` | No | Shared secret for HMAC-SHA256 payload signing |

Set these in your environment or in `ops/config/angelgrid.env`.

### Payload Format

Every webhook delivery is a JSON POST with the following structure:

```json
{
  "source": "angelclaw",
  "alert_type": "guardian_critical",
  "title": "Blocked rm -rf on production host",
  "severity": "critical",
  "details": {
    "agent_id": "node-prod-01",
    "matched_rule_id": "block-shell-destructive-rm",
    "command": "[REDACTED by AngelClaw]"
  },
  "tenant_id": "acme-corp",
  "related_event_ids": ["evt-abc123", "evt-def456"],
  "timestamp": "2026-02-16T14:30:00.000000+00:00"
}
```

### HMAC Verification

When `ANGELCLAW_WEBHOOK_SECRET` is configured, every request includes an `X-AngelClaw-Signature` header:

```
X-AngelClaw-Signature: sha256=<hex-encoded HMAC-SHA256 digest>
```

The signature is computed over the raw JSON request body using the shared secret as the key.

#### Example: Python Verification

```python
import hashlib
import hmac

def verify_angelclaw_signature(
    body: bytes,
    signature_header: str,
    secret: str,
) -> bool:
    """Verify the X-AngelClaw-Signature header from an AngelClaw webhook.

    Args:
        body: Raw request body bytes.
        signature_header: Value of the X-AngelClaw-Signature header.
        secret: The shared ANGELCLAW_WEBHOOK_SECRET.

    Returns:
        True if the signature is valid.
    """
    if not signature_header.startswith("sha256="):
        return False

    expected = hmac.new(
        secret.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()

    received = signature_header[len("sha256="):]
    return hmac.compare_digest(expected, received)
```

---

## Wazuh SIEM Integration

AngelClaw ships with pre-built Wazuh decoders and rules in `ops/wazuh/`.

### Architecture

```
ANGELNODE  ->  decisions.jsonl  ->  Filebeat  ->  Wazuh Manager  ->  Wazuh Dashboard
```

### Setup

1. Copy the decoder to the Wazuh Manager:

   ```bash
   cp ops/wazuh/angelgrid_decoder.xml /var/ossec/etc/decoders/
   ```

2. Copy the alert rules:

   ```bash
   cp ops/wazuh/angelgrid_rules.xml /var/ossec/etc/rules/
   ```

3. Deploy the Filebeat config on the ANGELNODE host:

   ```bash
   cp ops/wazuh/filebeat.yml /etc/filebeat/filebeat.yml
   ```

4. Restart services:

   ```bash
   systemctl restart wazuh-manager
   systemctl restart filebeat
   ```

### Files Reference

| File | Purpose |
|---|---|
| `ops/wazuh/angelgrid_decoder.xml` | Parses AngelClaw JSON log lines into Wazuh fields |
| `ops/wazuh/angelgrid_rules.xml` | Triggers Wazuh alerts for events with severity >= WARN |
| `ops/wazuh/filebeat.yml` | Filebeat config to tail ANGELNODE decision logs |

---

## Splunk HEC Integration

Forward AngelClaw alerts to Splunk via the HTTP Event Collector (HEC).

### Splunk HEC Configuration

Create an HEC token in Splunk, then configure the webhook to point to it:

```bash
export ANGELCLAW_WEBHOOK_URL="https://splunk.example.com:8088/services/collector/event"
export ANGELCLAW_WEBHOOK_SECRET=""  # Splunk HEC uses its own token auth
```

### Splunk inputs.conf

```ini
[http://angelclaw]
disabled = false
token = <your-hec-token>
sourcetype = angelclaw:alert
index = security
```

### Splunk props.conf

```ini
[angelclaw:alert]
SHOULD_LINEMERGE = false
KV_MODE = json
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%:z
TIME_PREFIX = "timestamp"\s*:\s*"
MAX_TIMESTAMP_LOOKAHEAD = 40
TRUNCATE = 65536
```

### Sample Splunk Search

```spl
index=security sourcetype="angelclaw:alert" severity="critical"
| stats count by alert_type, details.matched_rule_id
| sort -count
```

---

## Elastic Integration

Forward AngelClaw alerts to Elasticsearch for analysis in Kibana.

### Index Naming

All AngelClaw data should be indexed under the pattern:

```
angelclaw-alerts-*
```

For example: `angelclaw-alerts-2026.02.16`.

### Index Template

```json
{
  "index_patterns": ["angelclaw-alerts-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1
    },
    "mappings": {
      "properties": {
        "source":       { "type": "keyword" },
        "alert_type":   { "type": "keyword" },
        "title":        { "type": "text" },
        "severity":     { "type": "keyword" },
        "details":      { "type": "object", "dynamic": true },
        "tenant_id":    { "type": "keyword" },
        "related_event_ids": { "type": "keyword" },
        "timestamp":    { "type": "date" }
      }
    }
  }
}
```

### Logstash Pipeline (Optional)

If using Logstash as an intermediary between the webhook and Elasticsearch:

```ruby
input {
  http {
    port => 9600
    codec => json
  }
}

filter {
  mutate {
    add_field => { "[@metadata][index]" => "angelclaw-alerts-%{+YYYY.MM.dd}" }
  }
}

output {
  elasticsearch {
    hosts => ["https://es.example.com:9200"]
    index => "%{[@metadata][index]}"
    user => "elastic"
    password => "${ES_PASSWORD}"
  }
}
```

### Webhook Configuration for Elastic

Point the AngelClaw webhook directly at an Elasticsearch ingest endpoint or at Logstash:

```bash
# Direct to Elasticsearch (with an ingest pipeline)
export ANGELCLAW_WEBHOOK_URL="https://es.example.com:9200/angelclaw-alerts-_bulk"

# Or through Logstash
export ANGELCLAW_WEBHOOK_URL="http://logstash.example.com:9600"
```

### Kibana Dashboard Tip

Create an index pattern matching `angelclaw-alerts-*` in Kibana, then build visualizations using:

- **Severity breakdown**: Pie chart on the `severity` field
- **Alert timeline**: Date histogram on `timestamp` with `alert_type` split
- **Top triggered rules**: Terms aggregation on `details.matched_rule_id`
