from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.deps.auth import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.models.resource import Resource
from app.schemas.access import AccessCheckRead
from app.services.access_explain_service import explain_user_resource_access

router = APIRouter(prefix="/access", tags=["access"])


@router.get("/check", response_model=AccessCheckRead)
async def access_check(
    user_id: int = Query(..., ge=1),
    resource_id: int = Query(..., ge=1),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Авторизация: обычный пользователь может проверять только себя,
    # админ — любого пользователя.
    if not current_user.is_admin and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied for this user_id",
        )

    # Убедимся, что user и resource существуют и активны.
    user_result = await db.execute(
        select(User).where(User.id == user_id, User.is_active == True)  # noqa: E712
    )
    user = user_result.scalar_one_or_none()

    resource_result = await db.execute(
        select(Resource).where(
            Resource.id == resource_id,
            Resource.is_active == True,  # noqa: E712
        )
    )
    resource = resource_result.scalar_one_or_none()

    if not user or not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User or resource not found",
        )

    # Вызываем explain-слой как source of truth.
    explain: dict[str, Any] = await explain_user_resource_access(
        db=db,
        user_id=user_id,
        resource_id=resource_id,
    )

    decision = explain.get("decision", "deny")
    reason = explain.get("reason", "implicit deny")
    matched_policies = explain.get("matched_policies") or []
    winning_policy = explain.get("winning_policy")

    allowed = decision == "allow"

    return AccessCheckRead(
        user_id=user_id,
        resource_id=resource_id,
        allowed=allowed,
        decision=decision,
        reason=reason,
        matched_policies=matched_policies,
        winning_policy=winning_policy,
    )
