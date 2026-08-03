from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict

class TenantBase(BaseModel):
    name: str
    slug: str

class TenantCreate(TenantBase):
    pass

class TenantUpdate(BaseModel):
    name: str | None = None
    slug: str | None = None

class TenantRead(TenantBase):
    id: UUID
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
