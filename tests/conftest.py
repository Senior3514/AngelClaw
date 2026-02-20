"""Shared test fixtures for AngelClaw test suite."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Force test settings before importing app modules
os.environ["ANGELCLAW_AUTH_ENABLED"] = "false"
os.environ["ANGELCLAW_LOG_FORMAT"] = "text"
os.environ["ANGELGRID_DATABASE_URL"] = "sqlite:///test_angelgrid.db"

# Import all models that define tables so they register with Base.metadata
# before create_all is called. This prevents "no such table" errors.
from cloud.angelclaw.actions import ActionLogRow  # noqa: F401
from cloud.angelclaw.preferences import AngelClawPreferencesRow  # noqa: F401

# V2.4 — Fortress models
from cloud.db.models import (  # noqa: F401
    ApiKeyRow,
    BackupRecordRow,
    Base,
    CustomRoleRow,
    EventReplayRow,
    GuardianAlertRow,
    GuardianChangeRow,
    GuardianReportRow,
    NotificationChannelRow,
    NotificationRuleRow,
    OrganizationRow,
    PluginRegistrationRow,
    PolicySnapshotRow,
    QuarantineRecordRow,
    RemediationWorkflowRow,
    ThreatHuntQueryRow,
)
from cloud.db.session import get_db

# In-memory test database — StaticPool ensures all sessions share the same DB
TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSessionLocal = sessionmaker(bind=TEST_ENGINE)


def _override_get_db():
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create all tables in the test database once per session."""
    Base.metadata.create_all(bind=TEST_ENGINE)
    yield
    Base.metadata.drop_all(bind=TEST_ENGINE)


@pytest.fixture
def db():
    """Provide a clean database session for each test."""
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.rollback()
        db.close()


@pytest.fixture
def client():
    """Provide a FastAPI test client with overridden DB."""
    from cloud.api.server import app

    app.dependency_overrides[get_db] = _override_get_db
    # Reset rate limiter state between test clients so accumulated
    # requests from earlier tests don't trigger 429s.
    from cloud.middleware.security import _rate_windows

    _rate_windows.clear()
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
