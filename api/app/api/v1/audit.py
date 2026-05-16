from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db      # если у тебя get_db в другом месте — скажи, поправим
from app.models.audit_event import AuditEvent
from app.api.deps import get_current_admin

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/events")
async def list_audit_events(
    event_type: str | None = Query(default=None),
    user_id: int | None = Query(default=None),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0),
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(get_current_admin),
):
    q = select(AuditEvent).order_by(desc(AuditEvent.created_at))
    if event_type:
        q = q.where(AuditEvent.event_type == event_type)
    if user_id:
        q = q.where(AuditEvent.user_id == user_id)
    q = q.limit(limit).offset(offset)
    result = await db.execute(q)
    rows = result.scalars().all()
    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "user_id": e.user_id,
            "peer_id": e.peer_id,
            "resource_id": e.resource_id,
            "decision": e.decision,
            "ip_address": e.ip_address,
            "details": e.details,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in rows
    ]
