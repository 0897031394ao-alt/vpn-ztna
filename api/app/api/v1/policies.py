from typing import List, Set

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.group import user_group
from app.models.policy import Policy
from app.schemas.policy import PolicyCreate, PolicyRead
from app.services.peer_service import recalculate_peers_for_user

router = APIRouter(prefix="/policies", tags=["policies"])


async def get_policy_or_404(db: AsyncSession, policy_id: int) -> Policy:
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy or not policy.is_active:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


async def get_affected_user_ids_for_policy(
    db: AsyncSession,
    policy: Policy,
) -> list[int]:
    user_ids: Set[int] = set()

    if policy.user_id is not None:
        user_ids.add(policy.user_id)

    if policy.group_id is not None:
        result = await db.execute(
            select(user_group.c.user_id).where(user_group.c.group_id == policy.group_id)
        )
        user_ids.update(result.scalars().all())

    return sorted(user_ids)


async def recalculate_affected_peers_for_policy(
    db: AsyncSession,
    policy: Policy,
) -> None:
    user_ids = await get_affected_user_ids_for_policy(db, policy)
    for user_id in user_ids:
        await recalculate_peers_for_user(db, user_id)


@router.get("/", response_model=List[PolicyRead])
async def list_policies(
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Policy)
        .where(Policy.is_active == True)  # noqa: E712
        .order_by(Policy.priority.asc(), Policy.id.asc())
    )
    return list(result.scalars().all())


@router.get("/{policy_id}", response_model=PolicyRead)
async def get_policy(
    policy_id: int,
    db: AsyncSession = Depends(get_db),
):
    return await get_policy_or_404(db, policy_id)


@router.post("/", response_model=PolicyRead, status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: PolicyCreate,
    db: AsyncSession = Depends(get_db),
):
    policy = Policy(**payload.model_dump())
    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    await recalculate_affected_peers_for_policy(db, policy)
    return policy


@router.put("/{policy_id}", response_model=PolicyRead)
async def update_policy(
    policy_id: int,
    payload: PolicyCreate,
    db: AsyncSession = Depends(get_db),
):
    policy = await get_policy_or_404(db, policy_id)

    data = payload.model_dump()
    policy.name = data["name"]
    policy.description = data.get("description")
    policy.group_id = data.get("group_id")
    policy.user_id = data.get("user_id")
    policy.resource_id = data["resource_id"]
    policy.effect = data["effect"]
    policy.priority = data.get("priority", 100)
    policy.conditions = data.get("conditions")

    await db.commit()
    await db.refresh(policy)

    await recalculate_affected_peers_for_policy(db, policy)
    return policy


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: int,
    db: AsyncSession = Depends(get_db),
):
    policy = await get_policy_or_404(db, policy_id)

    policy.is_active = False
    await db.commit()
    await db.refresh(policy)

    await recalculate_affected_peers_for_policy(db, policy)

    return Response(status_code=status.HTTP_204_NO_CONTENT)

