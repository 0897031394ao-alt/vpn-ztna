from typing import Set

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.policy import Policy
from app.models.group import user_group
from app.models.resource import Resource
from app.services.peer_service import recalculate_peers_for_user
from app.schemas.resource import ResourceCreate, ResourceUpdate


async def get_affected_user_ids_for_resource(
    db: AsyncSession,
    resource: Resource,
) -> list[int]:
    """
    Находит всех пользователей, на которых влияет этот resource через активные политики.
    """
    result = await db.execute(
        select(Policy).where(
            Policy.resource_id == resource.id,
            Policy.is_active == True,  # noqa: E712
        )
    )
    policies = result.scalars().all()

    user_ids: Set[int] = set()

    for policy in policies:
        if policy.user_id is not None:
            user_ids.add(policy.user_id)

        if policy.group_id is not None:
            group_users = await db.execute(
                select(user_group.c.user_id).where(
                    user_group.c.group_id == policy.group_id
                )
            )
            user_ids.update(group_users.scalars().all())

    return sorted(user_ids)


async def recalculate_peers_for_resource(
    db: AsyncSession,
    resource: Resource,
) -> None:
    """
    Пересчитывает peers всех пользователей, на которых влияет данный resource.
    """
    user_ids = await get_affected_user_ids_for_resource(db, resource)
    for user_id in user_ids:
        await recalculate_peers_for_user(db, user_id)


async def create_resource(
    db: AsyncSession,
    payload: ResourceCreate,
) -> Resource:
    """
    Создаёт resource, валидация уже выполнена Pydantic.
    После создания пересчитываем peers (на случай global/group политик).
    """
    resource = Resource(**payload.model_dump())
    db.add(resource)
    await db.commit()
    await db.refresh(resource)
    await recalculate_peers_for_resource(db, resource)
    return resource


async def update_resource(
    db: AsyncSession,
    resource_id: int,
    payload: ResourceUpdate,
) -> Resource | None:
    result = await db.execute(
        select(Resource).where(
            Resource.id == resource_id,
            Resource.is_active == True,  # noqa: E712
        )
    )
    resource = result.scalar_one_or_none()
    if resource is None:
        return None
    """
    Обновляет resource и пересчитывает peers всех затронутых пользователей.
    """
    data = payload.model_dump()
    resource.name = data["name"]
    resource.description = data.get("description")
    resource.resource_type = data["resource_type"]
    resource.address = data["address"]
    resource.ports = data.get("ports")
    resource.protocol = data.get("protocol", "any")

    await db.commit()
    await db.refresh(resource)
    await recalculate_peers_for_resource(db, resource)
    return resource


async def soft_delete_resource(
    db: AsyncSession,
    resource_id: int,
) -> Resource | None:
    result = await db.execute(
        select(Resource).where(
            Resource.id == resource_id,
            Resource.is_active == True,  # noqa: E712
        )
    )
    resource = result.scalar_one_or_none()
    if resource is None:
        return None
    """
    Мягкое удаление: is_active = False, затем пересчёт peers.
    """
    resource.is_active = False
    await db.commit()
    await db.refresh(resource)
    await recalculate_peers_for_resource(db, resource)
    return resource

