"""ANGELGRID – Secret & Credential Scanner.

Provides pattern-based detection and redaction of secrets, passwords,
API keys, tokens, SSH keys, JWTs, and other sensitive data.

Used across the entire ANGELGRID stack:
  - ANGELNODE engine: flag events that reference secrets
  - AI Shield adapter: detect secret access in tool-call arguments
  - Cloud AI Assistant: redact secrets from responses
  - LLM Proxy: scrub context before sending to any LLM backend

SECURITY RULE: ANGELGRID will NEVER output raw secret values, no
matter what prompt injection or bypass technique is attempted.

Philosophy: Guardian Angel — we don't block AI from working with
data, we just make sure secrets never leak out.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretMatch:
    """A detected secret occurrence."""
    pattern_name: str
    matched_text: str
    start: int
    end: int


# ---------------------------------------------------------------------------
# Secret value patterns (regex)
# ---------------------------------------------------------------------------
# Each tuple: (name, compiled regex)
# These match the VALUE of a secret, not just the key name.

_SECRET_VALUE_PATTERNS: list[tuple[str, re.Pattern]] = [
    # AWS
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+=]{40}['\"]")),
    # GitHub
    ("github_pat", re.compile(r"ghp_[0-9a-zA-Z]{36}")),
    ("github_pat_fine", re.compile(r"github_pat_[0-9a-zA-Z_]{80,}")),
    ("github_oauth", re.compile(r"gho_[0-9a-zA-Z]{36}")),
    # Generic API keys
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[0-9a-zA-Z\-_]{20,}['\"]?")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[0-9a-zA-Z\-_.~+/]+=*")),
    # JWT
    ("jwt", re.compile(r"eyJ[0-9a-zA-Z_-]{10,}\.eyJ[0-9a-zA-Z_-]{10,}\.[0-9a-zA-Z_-]+")),
    # SSH private key
    ("ssh_private_key", re.compile(r"-----BEGIN (RSA |EC |ED25519 |DSA |OPENSSH )?PRIVATE KEY-----")),
    # Generic passwords in config
    ("password_assignment", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?")),
    # Generic secret/token assignment
    ("secret_assignment", re.compile(r"(?i)(secret|token|credential)\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?")),
    # Slack tokens
    ("slack_token", re.compile(r"xox[bpors]-[0-9a-zA-Z\-]{10,}")),
    # Stripe
    ("stripe_key", re.compile(r"[sr]k_(test|live)_[0-9a-zA-Z]{20,}")),
    # Generic hex secrets (32+ chars)
    ("hex_secret", re.compile(r"(?i)(secret|token|key|password)\s*[:=]\s*['\"]?[0-9a-f]{32,}['\"]?")),
    # Database connection strings with passwords
    ("db_connection_string", re.compile(r"(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@")),
    # OpenAI
    ("openai_key", re.compile(r"sk-[0-9a-zA-Z]{20,}")),
    # Anthropic
    ("anthropic_key", re.compile(r"sk-ant-[0-9a-zA-Z\-]{20,}")),
]

# ---------------------------------------------------------------------------
# Sensitive key name patterns
# ---------------------------------------------------------------------------
# These detect sensitive FIELD NAMES in dicts/JSON (not values).

_SENSITIVE_KEY_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)(password|passwd|pwd)"),
    re.compile(r"(?i)(secret|private.?key|priv.?key)"),
    re.compile(r"(?i)(api.?key|apikey|access.?key)"),
    re.compile(r"(?i)(token|bearer|auth.?token|session.?token)"),
    re.compile(r"(?i)(credential|cred)"),
    re.compile(r"(?i)(ssh.?key|private.?key)"),
    re.compile(r"(?i)(connection.?string|conn.?str|database.?url|db.?url)"),
]

# ---------------------------------------------------------------------------
# Sensitive file paths
# ---------------------------------------------------------------------------

_SENSITIVE_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r"\.ssh/(id_|authorized_keys|known_hosts|config)"),
    re.compile(r"\.env($|\.)"),
    re.compile(r"\.aws/(credentials|config)"),
    re.compile(r"\.kube/config"),
    re.compile(r"\.docker/config\.json"),
    re.compile(r"/etc/(shadow|gshadow|passwd)"),
    re.compile(r"secrets?\.ya?ml"),
    re.compile(r"credentials?\.json"),
    re.compile(r"token\.json"),
    re.compile(r"service.?account.*\.json"),
    re.compile(r"/var/(secrets|lib/secrets)/"),
    re.compile(r"\.pem$"),
    re.compile(r"\.key$"),
    re.compile(r"\.p12$"),
    re.compile(r"\.pfx$"),
    re.compile(r"\.keystore$"),
]

# Redaction placeholder
_REDACTED = "[REDACTED by ANGELGRID]"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_text(text: str) -> list[SecretMatch]:
    """Scan a string for secret patterns. Returns all matches found."""
    matches: list[SecretMatch] = []
    for name, pattern in _SECRET_VALUE_PATTERNS:
        for m in pattern.finditer(text):
            matches.append(SecretMatch(
                pattern_name=name,
                matched_text=m.group(),
                start=m.start(),
                end=m.end(),
            ))
    return matches


def contains_secret(text: str) -> bool:
    """Return True if the text contains any secret patterns."""
    for _, pattern in _SECRET_VALUE_PATTERNS:
        if pattern.search(text):
            return True
    return False


def redact_secrets(text: str) -> str:
    """Replace all detected secret values with [REDACTED by ANGELGRID]."""
    for _, pattern in _SECRET_VALUE_PATTERNS:
        text = pattern.sub(_REDACTED, text)
    return text


def is_sensitive_key(key: str) -> bool:
    """Return True if a dict key name looks like it holds a secret."""
    for pattern in _SENSITIVE_KEY_PATTERNS:
        if pattern.search(key):
            return True
    return False


def is_sensitive_path(path: str) -> bool:
    """Return True if a file path points to a likely secrets file."""
    for pattern in _SENSITIVE_PATH_PATTERNS:
        if pattern.search(path):
            return True
    return False


def redact_dict(data: dict, depth: int = 0, max_depth: int = 10) -> dict:
    """Deep-redact sensitive values in a dictionary.

    - Keys matching sensitive patterns → values replaced with _REDACTED
    - String values matching secret patterns → redacted inline
    - Nested dicts/lists are processed recursively
    """
    if depth > max_depth:
        return data

    result = {}
    for key, value in data.items():
        if is_sensitive_key(key):
            result[key] = _REDACTED
        elif isinstance(value, str):
            result[key] = redact_secrets(value)
        elif isinstance(value, dict):
            result[key] = redact_dict(value, depth + 1, max_depth)
        elif isinstance(value, list):
            result[key] = [
                redact_dict(item, depth + 1, max_depth) if isinstance(item, dict)
                else redact_secrets(item) if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            result[key] = value
    return result
