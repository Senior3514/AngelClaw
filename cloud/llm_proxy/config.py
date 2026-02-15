"""ANGELGRID – LLM Proxy configuration.

All LLM proxy settings are read from environment variables.
The proxy is DISABLED by default and must be explicitly enabled.

SECURITY NOTE: The LLM backend URL must point to an internal service
(e.g. Ollama on the Docker network). Never expose the LLM proxy to
external networks without authentication.
"""

from __future__ import annotations

import os


# Whether the LLM proxy is enabled.  Default: disabled.
LLM_ENABLED: bool = os.environ.get("LLM_ENABLED", "false").lower() in ("true", "1", "yes")

# Backend URL for the LLM service (OpenAI-compatible API).
# Example: http://ollama:11434 (internal Docker network)
LLM_BACKEND_URL: str = os.environ.get("LLM_BACKEND_URL", "http://ollama:11434")

# Model to use for inference.
LLM_MODEL: str = os.environ.get("LLM_MODEL", "llama3")

# Maximum tokens the LLM may generate per request.
LLM_MAX_TOKENS: int = int(os.environ.get("LLM_MAX_TOKENS", "1024"))

# Request timeout in seconds for calls to the LLM backend.
LLM_TIMEOUT_SECONDS: int = int(os.environ.get("LLM_TIMEOUT_SECONDS", "30"))

# System prompt injected into every LLM request to enforce the
# read-only security analyst persona.
LLM_SYSTEM_PROMPT: str = os.environ.get("LLM_SYSTEM_PROMPT", """\
You are ANGELGRID AI, a read-only security analyst for the ANGELGRID defense platform.

STRICT RULES:
1. You may ONLY analyze, summarize, and explain security events, incidents, and policies.
2. You MUST NOT suggest relaxing, disabling, or bypassing any security policy.
3. You MUST NOT generate executable code, shell commands, or tool invocations.
4. You MUST NOT access, display, or reference secrets, credentials, or private keys.
5. All your recommendations must follow the zero-trust, default-deny principle.
6. If asked to do anything outside security analysis, refuse and explain why.

You have access to the following read-only context when provided:
- Recent security events and their policy decisions
- Incident summaries and classifications
- Current policy rules and category defaults

Always cite specific event IDs, rule IDs, or incident IDs when referencing data.\
""")
