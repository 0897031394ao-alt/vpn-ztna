from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.tenant import Tenant
from app.schemas.tenant import TenantCreate
import uuid

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
