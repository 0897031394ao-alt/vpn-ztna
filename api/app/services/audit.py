from __future__ import annotations

from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_event import AuditEvent


async def write_audit_event(
    db: AsyncSession,
    event_type: str,
    *,
    user_id: int | None = None,
    peer_id: int | None = None,
    resource_id: int | None = None,
    decision: str | None = None,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
) -> AuditEvent:
    ip = None
    ua = None
    if request:
        forwarded = request.headers.get("X-Forwarded-For")
        ip = forwarded.split(",")[0].strip() if forwarded else request.client.host if request.client else None
        ua = request.headers.get("User-Agent")

    event = AuditEvent(
        event_type=event_type,
        user_id=user_id,
        peer_id=peer_id,
        resource_id=resource_id,
        decision=decision,
        ip_address=ip,
        user_agent=ua,
        details=details or {},
    )
    db.add(event)
    await db.flush()   # получаем id без коммита — коммит делает вызывающий код
    return event
