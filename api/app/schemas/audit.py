from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuditEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_type: str
    user_id: int | None = None
    peer_id: int | None = None
    resource_id: int | None = None
    decision: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None


class AuditEventListRead(BaseModel):
    items: list[AuditEventRead]
    total: int
    limit: int
    offset: int

