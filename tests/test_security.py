"""Tests for security middleware and secret protection."""

from shared.security.secret_scanner import (
    contains_secret,
    is_sensitive_key,
    is_sensitive_path,
    redact_dict,
    redact_secrets,
)


def test_secret_detection():
    assert contains_secret("AKIAIOSFODNN7EXAMPLE")
    assert contains_secret("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")
    assert contains_secret("sk-ant-abc123def456ghi789jkl")
    assert not contains_secret("hello world")
    assert not contains_secret("")


def test_sensitive_keys():
    assert is_sensitive_key("password")
    assert is_sensitive_key("api_key")
    assert is_sensitive_key("secret_token")
    assert not is_sensitive_key("username")
    assert not is_sensitive_key("file_path")


def test_sensitive_paths():
    assert is_sensitive_path(".env")
    assert is_sensitive_path("/etc/shadow")
    assert is_sensitive_path("~/.ssh/id_rsa")
    assert not is_sensitive_path("README.md")


def test_redact_secrets():
    text = "Key: sk-ant-abc123def456ghi789jkl012"
    redacted = redact_secrets(text)
    assert "sk-ant-" not in redacted
    assert "REDACTED" in redacted


def test_redact_dict():
    data = {"username": "admin", "password": "secret123", "config": {"api_key": "sk-123"}}
    redacted = redact_dict(data)
    assert redacted["username"] == "admin"
    assert "REDACTED" in str(redacted["password"])
    assert "REDACTED" in str(redacted["config"]["api_key"])


def test_wazuh_client_disabled():
    """Wazuh client should be disabled when no URL is configured."""
    from cloud.integrations.wazuh_client import WazuhClient

    client = WazuhClient()
    assert not client.enabled


def test_structured_logger_imports():
    """Structured logger components should import cleanly."""
    from cloud.services.structured_logger import (
        get_correlation_id,
        setup_structured_logging,
    )

    assert callable(setup_structured_logging)
    assert callable(get_correlation_id)
