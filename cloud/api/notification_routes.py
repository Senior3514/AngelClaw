"""AngelClaw Cloud -- Notification API Routes.

REST endpoints for managing notification channels and routing rules.
Supports CRUD for channels (Slack, Discord, generic webhook) and
routing rules that map severity/alert-type filters to channels.

Router prefix: /api/v1/notifications
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from cloud.db.models import NotificationChannelRow, NotificationRuleRow
from cloud.db.session import get_db
from cloud.services.notifications import notification_router

logger = logging.getLogger("angelgrid.cloud.notification_api")

router = APIRouter(prefix="/api/v1/notifications", tags=["Notifications"])


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class ChannelCreateRequest(BaseModel):
    """Body for creating a notification channel."""

    name: str = Field(..., min_length=1, max_length=128, description="Channel display name")
    channel_type: str = Field(..., description="Channel type: slack, discord, or webhook")
    config: dict[str, Any] = Field(
        ..., description="Channel-specific config (must include webhook_url)"
    )


class ChannelUpdateRequest(BaseModel):
    """Body for updating a notification channel."""

    name: Optional[str] = Field(default=None, max_length=128)
    config: Optional[dict[str, Any]] = None
    enabled: Optional[bool] = None


class ChannelResponse(BaseModel):
    """Serialised notification channel."""

    id: str
    tenant_id: str
    name: str
    channel_type: str
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: str = "true"
    created_at: datetime


class RuleCreateRequest(BaseModel):
    """Body for creating a notification routing rule."""

    channel_id: str = Field(..., description="Target channel ID")
    min_severity: str = Field(
        default="high",
        description="Minimum severity to trigger (info/low/warn/medium/high/critical)",
    )
    alert_types: list[str] = Field(
        default_factory=list,
        description="Alert types to match (empty list matches all)",
    )


class RuleResponse(BaseModel):
    """Serialised notification routing rule."""

    id: str
    tenant_id: str
    channel_id: str
    min_severity: str = "high"
    alert_types: list[str] = Field(default_factory=list)
    enabled: str = "true"
    created_at: datetime


class TestResult(BaseModel):
    """Result of a test-notification attempt."""

    success: bool
    channel_id: str
    message: str


# ---------------------------------------------------------------------------
# Auth / tenant dependency
# ---------------------------------------------------------------------------


async def _require_tenant(
    x_tenant_id: Optional[str] = Header(default=None),
) -> str:
    """Extract tenant from X-TENANT-ID header, defaulting to dev-tenant."""
    return x_tenant_id or "dev-tenant"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ch_row_to_response(row: NotificationChannelRow) -> ChannelResponse:
    """Convert a NotificationChannelRow to a Pydantic response model."""
    return ChannelResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        channel_type=row.channel_type,
        config=row.config or {},
        enabled=row.enabled or "true",
        created_at=row.created_at,
    )


def _rule_row_to_response(row: NotificationRuleRow) -> RuleResponse:
    """Convert a NotificationRuleRow to a Pydantic response model."""
    return RuleResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        channel_id=row.channel_id,
        min_severity=row.min_severity or "high",
        alert_types=row.alert_types or [],
        enabled=row.enabled or "true",
        created_at=row.created_at,
    )


# ===================================================================
# Channel endpoints
# ===================================================================


# ---------------------------------------------------------------------------
# POST /api/v1/notifications/channels  --  Create channel
# ---------------------------------------------------------------------------


@router.post(
    "/channels",
    response_model=ChannelResponse,
    summary="Create a notification channel",
    status_code=201,
)
def create_channel(
    body: ChannelCreateRequest,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> ChannelResponse:
    """Create a new notification channel for the tenant.

    Supported channel types: ``slack``, ``discord``, ``webhook``.
    The ``config`` object must include at least a ``webhook_url`` key.
    """
    valid_types = {"slack", "discord", "webhook"}
    if body.channel_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid channel_type '{body.channel_type}'. Must be one of: {sorted(valid_types)}"
            ),
        )

    if "webhook_url" not in body.config:
        raise HTTPException(
            status_code=400,
            detail="config must include a 'webhook_url' key",
        )

    row = NotificationChannelRow(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        name=body.name,
        channel_type=body.channel_type,
        config=body.config,
        enabled="true",
        created_at=datetime.now(timezone.utc),
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    logger.info(
        "[API] Created notification channel '%s' (%s) for tenant %s",
        row.name,
        row.channel_type,
        tenant_id,
    )
    return _ch_row_to_response(row)


# ---------------------------------------------------------------------------
# GET /api/v1/notifications/channels  --  List channels
# ---------------------------------------------------------------------------


@router.get(
    "/channels",
    response_model=list[ChannelResponse],
    summary="List notification channels",
)
def list_channels(
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> list[ChannelResponse]:
    """Return all notification channels for the tenant."""
    rows = (
        db.query(NotificationChannelRow)
        .filter(NotificationChannelRow.tenant_id == tenant_id)
        .order_by(NotificationChannelRow.created_at.desc())
        .all()
    )
    return [_ch_row_to_response(r) for r in rows]


# ---------------------------------------------------------------------------
# PUT /api/v1/notifications/channels/{channel_id}  --  Update channel
# ---------------------------------------------------------------------------


@router.put(
    "/channels/{channel_id}",
    response_model=ChannelResponse,
    summary="Update a notification channel",
)
def update_channel(
    channel_id: str,
    body: ChannelUpdateRequest,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> ChannelResponse:
    """Update an existing notification channel's name, config, or enabled state."""
    row = (
        db.query(NotificationChannelRow)
        .filter(
            NotificationChannelRow.id == channel_id,
            NotificationChannelRow.tenant_id == tenant_id,
        )
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail=f"Channel {channel_id} not found")

    if body.name is not None:
        row.name = body.name
    if body.config is not None:
        row.config = body.config
    if body.enabled is not None:
        row.enabled = "true" if body.enabled else "false"

    db.commit()
    db.refresh(row)

    logger.info(
        "[API] Updated notification channel '%s' (%s) for tenant %s",
        row.name,
        row.channel_type,
        tenant_id,
    )
    return _ch_row_to_response(row)


# ---------------------------------------------------------------------------
# DELETE /api/v1/notifications/channels/{channel_id}  --  Delete channel
# ---------------------------------------------------------------------------


@router.delete(
    "/channels/{channel_id}",
    summary="Delete a notification channel",
)
def delete_channel(
    channel_id: str,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Delete a notification channel and all associated routing rules.

    Returns a confirmation message on success, 404 if not found.
    """
    row = (
        db.query(NotificationChannelRow)
        .filter(
            NotificationChannelRow.id == channel_id,
            NotificationChannelRow.tenant_id == tenant_id,
        )
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail=f"Channel {channel_id} not found")

    # Cascade-delete associated rules
    db.query(NotificationRuleRow).filter(
        NotificationRuleRow.channel_id == channel_id,
    ).delete(synchronize_session="fetch")

    db.delete(row)
    db.commit()

    logger.info(
        "[API] Deleted notification channel '%s' (%s) for tenant %s",
        row.name,
        row.channel_type,
        tenant_id,
    )
    return {"detail": f"Channel {channel_id} deleted"}


# ---------------------------------------------------------------------------
# POST /api/v1/notifications/channels/{channel_id}/test  --  Test channel
# ---------------------------------------------------------------------------


@router.post(
    "/channels/{channel_id}/test",
    response_model=TestResult,
    summary="Send a test notification",
)
def test_channel(
    channel_id: str,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> TestResult:
    """Send a test notification through the specified channel.

    Useful for validating webhook URLs and credentials during setup.
    """
    try:
        success = notification_router.send_test(db=db, channel_id=channel_id)
        return TestResult(
            success=success,
            channel_id=channel_id,
            message="Test notification sent" if success else "Test notification failed",
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("[API] Test notification error for channel %s", channel_id[:8])
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ===================================================================
# Rule endpoints
# ===================================================================


# ---------------------------------------------------------------------------
# POST /api/v1/notifications/rules  --  Create routing rule
# ---------------------------------------------------------------------------


@router.post(
    "/rules",
    response_model=RuleResponse,
    summary="Create a notification routing rule",
    status_code=201,
)
def create_rule(
    body: RuleCreateRequest,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> RuleResponse:
    """Create a routing rule that maps alert criteria to a notification channel.

    The rule fires when the alert severity is >= ``min_severity`` AND (if
    ``alert_types`` is non-empty) the alert type matches one of the listed types.
    """
    # Validate that the target channel exists and belongs to this tenant
    ch = (
        db.query(NotificationChannelRow)
        .filter(
            NotificationChannelRow.id == body.channel_id,
            NotificationChannelRow.tenant_id == tenant_id,
        )
        .first()
    )
    if not ch:
        raise HTTPException(
            status_code=404,
            detail=f"Channel {body.channel_id} not found for tenant {tenant_id}",
        )

    valid_severities = {"info", "low", "warn", "medium", "high", "critical"}
    if body.min_severity not in valid_severities:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid min_severity '{body.min_severity}'."
                f" Must be one of: {sorted(valid_severities)}"
            ),
        )

    row = NotificationRuleRow(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        channel_id=body.channel_id,
        min_severity=body.min_severity,
        alert_types=body.alert_types,
        enabled="true",
        created_at=datetime.now(timezone.utc),
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    logger.info(
        "[API] Created notification rule %s -> channel %s (min_severity=%s) for tenant %s",
        row.id[:8],
        body.channel_id[:8],
        body.min_severity,
        tenant_id,
    )
    return _rule_row_to_response(row)


# ---------------------------------------------------------------------------
# GET /api/v1/notifications/rules  --  List rules
# ---------------------------------------------------------------------------


@router.get(
    "/rules",
    response_model=list[RuleResponse],
    summary="List notification routing rules",
)
def list_rules(
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> list[RuleResponse]:
    """Return all notification routing rules for the tenant."""
    rows = (
        db.query(NotificationRuleRow)
        .filter(NotificationRuleRow.tenant_id == tenant_id)
        .order_by(NotificationRuleRow.created_at.desc())
        .all()
    )
    return [_rule_row_to_response(r) for r in rows]


# ---------------------------------------------------------------------------
# DELETE /api/v1/notifications/rules/{rule_id}  --  Delete rule
# ---------------------------------------------------------------------------


@router.delete(
    "/rules/{rule_id}",
    summary="Delete a notification routing rule",
)
def delete_rule(
    rule_id: str,
    tenant_id: str = Depends(_require_tenant),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Delete a notification routing rule.

    Returns a confirmation message on success, 404 if not found.
    """
    row = (
        db.query(NotificationRuleRow)
        .filter(
            NotificationRuleRow.id == rule_id,
            NotificationRuleRow.tenant_id == tenant_id,
        )
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    db.delete(row)
    db.commit()

    logger.info(
        "[API] Deleted notification rule %s for tenant %s",
        rule_id[:8],
        tenant_id,
    )
    return {"detail": f"Rule {rule_id} deleted"}
