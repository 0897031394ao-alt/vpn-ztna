from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from app.db.base import Base


class JSONVariant(TypeDecorator):
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


class AuditEventType(str, enum.Enum):
    AUTH_LOGIN_SUCCESS = "auth.login_succeeded"
    AUTH_LOGIN_FAIL = "auth.login_failed"
    AUTH_LOGOUT = "auth.logout"
    PEER_ENROLLED = "peer.enrolled"
    PEER_RECREATED = "peer.recreated"
    PEER_CONFIG_DOWNLOADED = "peer.config_downloaded"
    PEER_RECALCULATED = "peer.recalculated"
    POLICY_EXPLAIN_VIEWED = "policy.explain_viewed"
    ACCESS_DECISION = "access.decision_computed"
    POLICY_CREATED = "policy.created"
    POLICY_DELETED = "policy.deleted"
    RESOURCE_CREATED = "resource.created"
    RESOURCE_DELETED = "resource.deleted"


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    peer_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resource_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    decision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONVariant(),
        nullable=False,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )
