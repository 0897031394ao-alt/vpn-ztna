from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.resource import Resource
from app.schemas.resource import ResourceCreate, ResourceUpdate, ResourceRead
from app.services.resource_service import (
    create_resource as create_resource_service,
    update_resource as update_resource_service,
    soft_delete_resource,
)

router = APIRouter(prefix="/resources", tags=["resources"])


@router.get("/", response_model=list[ResourceRead])
async def list_resources(
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Resource)
        .where(Resource.is_active == True)  # noqa: E712
        .order_by(Resource.id)
    )
    return list(result.scalars().all())


@router.get("/{resource_id}", response_model=ResourceRead)
async def get_resource(
    resource_id: int,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Resource).where(Resource.id == resource_id))
    resource = result.scalar_one_or_none()
    if not resource or not resource.is_active:
        raise HTTPException(status_code=404, detail="Resource not found")
    return resource


@router.post("/", response_model=ResourceRead)
async def create_resource(
    payload: ResourceCreate,
    db: AsyncSession = Depends(get_db),
):
    return await create_resource_service(db, payload)


@router.put("/{resource_id}", response_model=ResourceRead)
async def update_resource(
    resource_id: int,
    payload: ResourceUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Resource).where(Resource.id == resource_id))
    resource = result.scalar_one_or_none()
    if not resource or not resource.is_active:
        raise HTTPException(status_code=404, detail="Resource not found")
    return await update_resource(db, resource, payload)


@router.delete("/{resource_id}", status_code=204)
async def delete_resource(
    resource_id: int,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Resource).where(Resource.id == resource_id))
    resource = result.scalar_one_or_none()
    if not resource or not resource.is_active:
        raise HTTPException(status_code=404, detail="Resource not found")
    await soft_delete_resource(db, resource)
    return None

