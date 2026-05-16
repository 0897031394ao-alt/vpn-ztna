from datetime import datetime
from pydantic import BaseModel, model_validator
from app.models.policy import PolicyEffect


class PolicyCreate(BaseModel):
    name: str
    description: str | None = None
    group_id: int | None = None
    user_id: int | None = None
    resource_id: int
    effect: PolicyEffect = PolicyEffect.allow
    priority: int = 100
    conditions: str | None = None

    @model_validator(mode="after")
    def check_subject(self):
        if self.group_id is None and self.user_id is None:
            raise ValueError("Необходимо указать group_id или user_id")
        if self.group_id is not None and self.user_id is not None:
            raise ValueError("Укажите только одно: group_id или user_id")
        return self


class PolicyRead(BaseModel):
    id: int
    name: str
    description: str | None = None
    group_id: int | None = None
    user_id: int | None = None
    resource_id: int
    effect: PolicyEffect
    priority: int
    conditions: str | None = None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
