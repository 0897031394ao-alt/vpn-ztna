from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_event import AuditEvent
from app.models.user import User
from app.models.peer import Peer
from app.models.resource import Resource


async def log_event(
    db: AsyncSession,
    *,
    action: str,
    current_user: User | None = None,
    peer: Peer | None = None,
    resource: Resource | None = None,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
) -> None:
    ip = None
    ua = None
    if request:
        forwarded = request.headers.get("X-Forwarded-For")
        ip = forwarded.split(",")[0].strip() if forwarded else (
            request.client.host if request.client else None
        )
        ua = request.headers.get("User-Agent")

    event = AuditEvent(
        event_type=action,
        user_id=current_user.id if current_user else None,
        peer_id=peer.id if peer else None,
        resource_id=resource.id if resource else None,
        details=details or {},
        ip_address=ip,
        user_agent=ua,
    )
    db.add(event)
