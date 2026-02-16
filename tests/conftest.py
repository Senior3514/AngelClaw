"""Shared test fixtures for AngelClaw test suite."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Force test settings before importing app modules
os.environ["ANGELCLAW_AUTH_ENABLED"] = "false"
os.environ["ANGELCLAW_LOG_FORMAT"] = "text"
os.environ["ANGELGRID_DATABASE_URL"] = "sqlite:///test_angelgrid.db"

from cloud.db.models import Base
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
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
