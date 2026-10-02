from typing import Any
from hashlib import sha256
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_event import AuditEvent
from app.models.user import User
from app.models.peer import Peer
from app.models.resource import Resource


SENSITIVE_DETAIL_KEYS = {
    "session_id",
    "refresh_token",
    "access_token",
    "token",
    "private_key",
    "config",
    "config_ini",
    "qr_payload",
}


def _mask_session_id(value: str | None) -> str | None:
    if not value:
        return value
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()[:16]


def _sanitize_detail_value(key: str | None, value: Any) -> Any:
    if key in SENSITIVE_DETAIL_KEYS:
        if key == "session_id" and isinstance(value, str):
            return _mask_session_id(value)
        return "<redacted>"

    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for nested_key, nested_value in value.items():
            sanitized[nested_key] = _sanitize_detail_value(nested_key, nested_value)
        return sanitized

    if isinstance(value, list):
        return [_sanitize_detail_value(key, item) for item in value]

    if isinstance(value, tuple):
        return tuple(_sanitize_detail_value(key, item) for item in value)

    if isinstance(value, str):
        return value.replace("\r", "\\r").replace("\n", "\\n")

    return value


def _sanitize_details(details: dict[str, Any] | None) -> dict[str, Any]:
    if not details:
        return {}

    return {
        key: _sanitize_detail_value(key, value)
        for key, value in details.items()
    }


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
        details=_sanitize_details(details),
        ip_address=ip,
        user_agent=ua,
    )
    db.add(event)
