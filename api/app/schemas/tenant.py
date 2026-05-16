from uuid import UUID
from datetime import datetime
from pydantic import BaseModel

class TenantBase(BaseModel):
    name: str
    slug: str

class TenantCreate(TenantBase):
    pass

class TenantRead(TenantBase):
    id: UUID
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True
