from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from app.models.group import Group
from app.schemas.group import GroupCreate, GroupUpdate


async def create_group(db: AsyncSession, payload: GroupCreate) -> Group:
    existing = await db.execute(select(Group).where(Group.name == payload.name))
    if existing.scalar_one_or_none():
        raise ValueError("Group with this name already exists")
    group = Group(name=payload.name, description=payload.description)
    db.add(group)
    await db.flush()
    return group


async def update_group(db: AsyncSession, group_id: int, payload: GroupUpdate) -> Group:
    group = await db.get(Group, group_id)
    if not group:
        raise ValueError("Group not found")
    if payload.name is not None:
        group.name = payload.name
    if payload.description is not None:
        group.description = payload.description
    if payload.is_active is not None:
        group.is_active = payload.is_active
    await db.flush()
    return group


async def soft_delete_group(db: AsyncSession, group_id: int) -> None:
    group = await db.get(Group, group_id)
    if not group:
        raise ValueError("Group not found")
    group.is_active = False
    await db.flush()


async def get_group_with_users(db: AsyncSession, group_id: int) -> Group | None:
    result = await db.execute(
        select(Group).options(selectinload(Group.users)).where(Group.id == group_id)
    )
    return result.scalar_one_or_none()
