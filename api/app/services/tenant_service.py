import uuid
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.tenant import Tenant
from app.schemas.tenant import TenantCreate, TenantUpdate

async def create_tenant(db: AsyncSession, payload: TenantCreate) -> Tenant:
    tenant = Tenant(
        id=uuid.uuid4(),
        name=payload.name,
        slug=payload.slug,
    )
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)
    return tenant

async def list_tenants(db: AsyncSession) -> list[Tenant]:
    result = await db.execute(select(Tenant))
    return result.scalars().all()

async def get_tenant(db: AsyncSession, tenant_id: uuid.UUID) -> Tenant | None:
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    return result.scalar_one_or_none()

async def update_tenant(db: AsyncSession, tenant_id: uuid.UUID, payload: TenantUpdate) -> Tenant:
    tenant = await get_tenant(db, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(tenant, key, value)
    await db.commit()
    await db.refresh(tenant)
    return tenant

async def delete_tenant(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    tenant = await get_tenant(db, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    await db.delete(tenant)
    await db.commit()

async def toggle_tenant(db: AsyncSession, tenant_id: uuid.UUID) -> Tenant:
    tenant = await get_tenant(db, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    tenant.is_active = not tenant.is_active
    await db.commit()
    await db.refresh(tenant)
    return tenant
