from typing import Any
from pydantic import BaseModel


class AccessCheckRead(BaseModel):
    user_id: int
    resource_id: int
    allowed: bool
    decision: str
    reason: str
    matched_policies: list[dict[str, Any]] = []
    winning_policy: dict[str, Any] | None = None
