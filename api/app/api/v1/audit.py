from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin
from app.core.deps import get_db
from app.models.audit_event import AuditEvent
from app.models.user import User
from app.schemas.audit import AuditEventListRead, AuditEventRead

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=AuditEventListRead)
async def list_audit_events(
    event_type: str | None = Query(default=None),
    user_id: int | None = Query(default=None, ge=1),
    peer_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    filters = []

    if event_type:
        filters.append(AuditEvent.event_type == event_type)
    if user_id is not None:
        filters.append(AuditEvent.user_id == user_id)
    if peer_id is not None:
        filters.append(AuditEvent.peer_id == peer_id)

    total_stmt = select(func.count()).select_from(AuditEvent)
    if filters:
        total_stmt = total_stmt.where(*filters)

    items_stmt = (
        select(AuditEvent)
        .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        .limit(limit)
        .offset(offset)
    )
    if filters:
        items_stmt = items_stmt.where(*filters)

    total_result = await db.execute(total_stmt)
    total = int(total_result.scalar_one() or 0)

    items_result = await db.execute(items_stmt)
    rows = items_result.scalars().all()

    return AuditEventListRead(
        items=[AuditEventRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )

