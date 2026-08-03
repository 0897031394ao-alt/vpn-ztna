from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.auth_session import AuthSession
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
    auto_error=False,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _coerce_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _extract_token_from_request(request: Request, bearer_token: str | None) -> str | None:
    if bearer_token:
        token = bearer_token.strip()
        return token or None

    cookie_val = request.cookies.get("access_token")
    if not cookie_val:
        return None

    cookie_val = cookie_val.strip()
    if not cookie_val:
        return None

    if cookie_val.startswith("Bearer "):
        cookie_val = cookie_val[len("Bearer ") :].strip()

    return cookie_val or None


def _credentials_exception() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    token = _extract_token_from_request(request, token)
    if not token:
        raise _credentials_exception()

    payload = decode_access_token(token)
    if not payload:
        raise _credentials_exception()

    sub = payload.get("sub")
    ver = payload.get("ver")
    sid = payload.get("sid")

    try:
        user_id = int(sub)
        token_version = int(ver)
        session_uuid = str(sid)
    except (TypeError, ValueError):
        raise _credentials_exception()

    user = await db.scalar(
        select(User).where(User.id == user_id)
    )
    if user is None:
        raise _credentials_exception()

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )

    if int(user.token_version) != token_version:
        raise _credentials_exception()

    auth_session = await db.scalar(
        select(AuthSession).where(
            AuthSession.session_uuid == session_uuid,
            AuthSession.user_id == user.id,
        )
    )
    if auth_session is None:
        raise _credentials_exception()

    now = _utcnow()
    expires_at = _coerce_utc(auth_session.expires_at)
    last_seen_at = _coerce_utc(auth_session.last_seen_at)

    if auth_session.is_revoked:
        raise _credentials_exception()

    if expires_at <= now:
        auth_session.is_revoked = True
        auth_session.revoked_at = now
        auth_session.last_seen_at = now

        if request.client and request.client.host:
            auth_session.ip_address = request.client.host

        user_agent = request.headers.get("user-agent")
        if user_agent:
            auth_session.user_agent = user_agent

        await db.commit()
        raise _credentials_exception()

    should_touch = (now - last_seen_at).total_seconds() >= 60

    if should_touch:
        auth_session.last_seen_at = now

        if request.client and request.client.host:
            auth_session.ip_address = request.client.host

        user_agent = request.headers.get("user-agent")
        if user_agent:
            auth_session.user_agent = user_agent

        await db.commit()

    request.state.session_uuid = auth_session.session_uuid
    request.state.auth_session_id = auth_session.id
    request.state.current_user_id = user.id

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
