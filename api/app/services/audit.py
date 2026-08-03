from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auditevent import AuditEvent


async def log_event(
    db: AsyncSession,
    *,
    action: str,
    current_user=None,
    peer=None,
    resource=None,
    details: dict[str, Any] | None = None,
    request=None,
) -> AuditEvent:
    event = AuditEvent(
        action=action,
        user_id=getattr(current_user, "id", None),
        peer_id=getattr(peer, "id", None),
        resource_id=getattr(resource, "id", None),
        ip_address=_client_ip(request),
        user_agent=_user_agent(request),
        details=details or {},
    )
    db.add(event)
    await db.flush()
    return event


def _client_ip(request) -> str | None:
    if request is None:
        return None
    forwarded = request.headers.get("x-forwarded-for") if hasattr(request, "headers") else None
    if forwarded:
        return forwarded.split(",")[0].strip()
    client = getattr(request, "client", None)
    if client:
        return getattr(client, "host", None)
    return None


def _user_agent(request) -> str | None:
    if request is None or not hasattr(request, "headers"):
        return None
    return request.headers.get("user-agent")
