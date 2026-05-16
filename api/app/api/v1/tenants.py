from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.tenant import Tenant
from app.schemas.tenant import TenantCreate, TenantRead
from app.services.tenant_service import create_tenant, list_tenants

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.post("/", response_model=TenantRead)
async def create_tenant_endpoint(
    payload: TenantCreate,
    db: AsyncSession = Depends(get_db),
):
    return await create_tenant(db, payload)


@router.get("/", response_model=list[TenantRead])
async def list_tenants_endpoint(
    db: AsyncSession = Depends(get_db),
):
    return await list_tenants(db)


@router.get("/{tenant_id}", response_model=TenantRead)
async def get_tenant_endpoint(
    tenant_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


@router.put("/{tenant_id}", response_model=TenantRead)
async def update_tenant_endpoint(
    tenant_id: UUID,
    payload: TenantCreate,
    db: AsyncSession = Depends(get_db),
):
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    tenant.name = payload.name
    tenant.slug = payload.slug

    await db.commit()
    await db.refresh(tenant)
    return tenant


@router.delete("/{tenant_id}")
async def delete_tenant_endpoint(
    tenant_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    await db.delete(tenant)
    await db.commit()
    return {"status": "deleted", "id": str(tenant_id)}


@router.post("/{tenant_id}/toggle", response_model=TenantRead)
async def toggle_tenant_endpoint(
    tenant_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    tenant.is_active = not tenant.is_active
    await db.commit()
    await db.refresh(tenant)
    return tenant

