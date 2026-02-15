# ANGELGRID ↔ Wazuh Integration

This directory contains configuration and rules for forwarding ANGELGRID events
to [Wazuh](https://wazuh.com/) — an open-source SIEM/XDR platform.

## Architecture

```
ANGELNODE  →  decisions.jsonl  →  Filebeat / rsyslog  →  Wazuh Manager  →  Wazuh Dashboard
```

1. **ANGELNODE** writes structured JSON decision logs to `decisions.jsonl`.
2. **Filebeat** (or rsyslog) tails the log file and forwards entries to the Wazuh Manager.
3. **Wazuh Manager** applies custom decoder and rules to parse ANGELGRID events and fire alerts.
4. **Wazuh Dashboard** displays alerts and allows analysts to investigate.

## Files

- `filebeat.yml` – Filebeat configuration to tail the ANGELGRID log file.
- `angelgrid_decoder.xml` – Wazuh decoder to parse ANGELGRID JSON log lines.
- `angelgrid_rules.xml` – Wazuh rules that trigger alerts for severity >= WARN.

## Setup

1. Copy `angelgrid_decoder.xml` to `/var/ossec/etc/decoders/` on the Wazuh Manager.
2. Copy `angelgrid_rules.xml` to `/var/ossec/etc/rules/` on the Wazuh Manager.
3. Install and configure Filebeat on the ANGELNODE host using `filebeat.yml`.
4. Restart the Wazuh Manager: `systemctl restart wazuh-manager`.
5. Restart Filebeat: `systemctl restart filebeat`.

## Testing

Send a test event through the ANGELNODE `/evaluate` endpoint with severity `high`
and verify that a Wazuh alert appears in the dashboard.
