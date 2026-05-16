from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.auth_session import AuthSession
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_access_token(token)
    if not payload:
        raise credentials_exception

    sub = payload.get("sub")
    ver = payload.get("ver")
    sid = payload.get("sid")

    if sub is None or ver is None or not sid:
        raise credentials_exception

    try:
        user_id = int(sub)
    except ValueError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )

    if user.token_version != ver:
        raise credentials_exception

    session_result = await db.execute(
        select(AuthSession).where(
            AuthSession.session_uuid == sid,
            AuthSession.user_id == user.id,
        )
    )
    auth_session = session_result.scalar_one_or_none()
    if auth_session is None:
        raise credentials_exception

    now = _utcnow()

    if auth_session.is_revoked:
        raise credentials_exception

    if auth_session.expires_at <= now:
        auth_session.is_revoked = True
        auth_session.revoked_at = now
        auth_session.last_seen_at = now
        await db.commit()
        raise credentials_exception

    should_touch = (
        auth_session.last_seen_at is None
        or (now - auth_session.last_seen_at).total_seconds() >= 60
    )

    if should_touch:
        auth_session.last_seen_at = now
        if request.client and request.client.host:
            auth_session.ip_address = request.client.host
        auth_session.user_agent = request.headers.get("user-agent") or auth_session.user_agent
        await db.commit()

    request.state.session_uuid = auth_session.session_uuid
    return user


async def get_current_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    return current_user


async def get_current_admin_or_self(
    user_id: int,
    current_user: User = Depends(get_current_user),
) -> User:
    if current_user.is_admin:
        return current_user
    if current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    return current_user
