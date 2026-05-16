from datetime import datetime

from pydantic import BaseModel, EmailStr, constr


class UserRegister(BaseModel):
    username: constr(min_length=3, max_length=64)
    email: EmailStr
    password: constr(min_length=8, max_length=128)


class UserLogin(BaseModel):
    username: str
    password: str


class TokenRead(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class UserMeRead(BaseModel):
    id: int
    uuid: str
    username: str
    email: EmailStr
    is_active: bool
    is_admin: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AuthSessionRead(BaseModel):
    session_uuid: str
    ip_address: str | None
    user_agent: str | None
    is_revoked: bool
    expires_at: datetime
    last_seen_at: datetime
    created_at: datetime
    revoked_at: datetime | None
    is_current: bool
    display_name: str
    device_type: str
    device_family: str | None
    os_family: str | None
    browser_family: str | None
    is_bot: bool


class AuthSessionListResponse(BaseModel):
    items: list[AuthSessionRead]


class CurrentSessionResponse(BaseModel):
    user: UserMeRead
    session: AuthSessionRead
