"""AngelClaw Cloud – Database session management.

Provides an async-compatible session factory.  Uses SQLite by default;
override DATABASE_URL environment variable for PostgreSQL.

SECURITY NOTE: Never embed credentials in this file.  Connection strings
with passwords must come from environment variables or a secrets manager.
"""

from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

DATABASE_URL = os.environ.get("ANGELGRID_DATABASE_URL", "sqlite:///angelgrid.db")

engine = create_engine(
    DATABASE_URL,
    echo=False,
    # SQLite-specific: allow same connection across threads for dev simplicity
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
)

SessionLocal = sessionmaker(bind=engine, class_=Session)


def get_db():
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
