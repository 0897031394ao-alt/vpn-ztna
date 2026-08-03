from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenRead(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenPayload(BaseModel):
    sub: str | None = None
    type: str | None = None
    ver: int | None = None
    sid: str | None = None
    jti: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: EmailStr
    is_active: bool
    is_admin: bool
    token_version: int
    created_at: datetime | None = None


class SessionRead(BaseModel):
    session_uuid: str
    created_at: datetime | None = None
    last_seen_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    is_current: bool = False
    is_revoked: bool = False
    ip_address: str | None = None
    user_agent: str | None = None


class CurrentSessionRead(SessionRead):
    is_current: bool = True


class SessionListRead(BaseModel):
    items: list[SessionRead]
