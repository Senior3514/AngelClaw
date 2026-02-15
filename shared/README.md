# Shared – Common Models, Security Helpers & Config Schemas

This package contains all data models, security utility functions, and configuration
schemas shared between ANGELNODE, ANGELGRID Cloud, and agentless connectors.

## Structure

- `models/` – Pydantic data models for AgentNode, Event, PolicyRule, PolicySet, Incident.
- `security/` – Cryptographic helpers, token validation, input sanitization.
- `config/` – Configuration schemas and environment variable handling.

## Usage

All other components import from `shared.models`:

```python
from shared.models.event import Event, EventCategory, Severity
from shared.models.policy import PolicyRule, PolicySet, PolicyAction
```
