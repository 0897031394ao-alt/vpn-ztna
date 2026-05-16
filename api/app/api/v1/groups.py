from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin
from app.db.session import get_db
from app.models.group import Group
from app.models.user import User
from app.schemas.group import GroupCreate, GroupRead

router = APIRouter(prefix="/groups", tags=["groups"])


@router.get("/", response_model=list[GroupRead])
async def list_groups(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(select(Group))
    return result.scalars().all()


@router.post("/", response_model=GroupRead)
async def create_group(
    payload: GroupCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(select(Group).where(Group.name == payload.name))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Group already exists")

    group = Group(**payload.model_dump())
    db.add(group)
    await db.commit()
    await db.refresh(group)
    return group
