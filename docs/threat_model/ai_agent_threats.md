# AngelClaw Threat Model – AI Agent Threats

## Threat Categories

### 1. Prompt Injection
- **Description**: Malicious instructions injected into AI agent context via user input, retrieved documents, or tool outputs.
- **AngelClaw Mitigation**: AI Shield adapter inspects tool-call arguments for known injection patterns. Policy rules can block tool calls with suspicious payloads.
- **OWASP AI Reference**: LLM01 – Prompt Injection

### 2. Data Exfiltration via Tool Use
- **Description**: An AI agent, under adversarial influence, uses tools (HTTP requests, file writes, shell commands) to exfiltrate sensitive data.
- **AngelClaw Mitigation**: Network and file-access events are evaluated against policy rules. Outbound POST to untrusted destinations triggers alerts/blocks.
- **OWASP AI Reference**: LLM06 – Sensitive Information Disclosure

### 3. Unauthorized Credential Access
- **Description**: AI agent attempts to read secrets, API keys, or credentials from environment, files, or databases.
- **AngelClaw Mitigation**: The `accesses_secrets` heuristic in the AI Shield flags tool calls that reference credential-related terms. Policy rules block these by default.
- **OWASP AI Reference**: LLM06 – Sensitive Information Disclosure

### 4. Excessive Agency / Privilege Escalation
- **Description**: An AI agent executes privileged operations (sudo, admin APIs, infrastructure changes) beyond its intended scope.
- **AngelClaw Mitigation**: Shell and system events with elevated privilege indicators are evaluated. High-risk tool names (bash, sudo, ssh) get elevated severity.
- **OWASP AI Reference**: LLM08 – Excessive Agency

### 5. Denial of Service via Resource Exhaustion
- **Description**: AI agent enters an infinite loop or spawns excessive processes/requests.
- **AngelClaw Mitigation**: Future rate-limiting sensors. Current: alert rules for rapid event generation from a single agent.

### 6. Supply Chain / Plugin Attacks
- **Description**: Malicious MCP servers, plugins, or tool definitions that redirect AI agent behavior.
- **AngelClaw Mitigation**: Policy rules can allowlist specific tool names and block unknown tools. Future: tool signature verification.
- **OWASP AI Reference**: LLM05 – Supply Chain Vulnerabilities

## Risk Matrix

| Threat                  | Likelihood | Impact   | Current Coverage |
|-------------------------|-----------|----------|-----------------|
| Prompt Injection        | High      | Critical | Partial         |
| Data Exfiltration       | High      | Critical | Partial         |
| Credential Access       | Medium    | Critical | Active          |
| Excessive Agency        | Medium    | High     | Active          |
| Resource Exhaustion     | Low       | Medium   | Planned         |
| Supply Chain Attack     | Low       | Critical | Planned         |
