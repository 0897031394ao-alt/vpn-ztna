from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
    verify_password,
)
from app.db.session import get_db
from app.models.auth_session import AuthSession
from app.models.user import User
from app.schemas.auth import (
    CurrentSessionRead,
    RefreshTokenRequest,
    SessionListRead,
    SessionRead,
    TokenRead,
    UserRead,
)
from app.services.audit_service import log_event

router = APIRouter(prefix="/auth", tags=["auth"])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def _user_agent(request: Request) -> str | None:
    return request.headers.get("user-agent")


def _session_to_read(session: AuthSession) -> SessionRead:
    return SessionRead(
        session_uuid=session.session_uuid,
        created_at=_as_utc(session.created_at),
        last_seen_at=_as_utc(session.last_seen_at),
        expires_at=_as_utc(session.expires_at),
        revoked_at=_as_utc(session.revoked_at),
        is_current=False,
        is_revoked=bool(session.is_revoked),
        ip_address=session.ip_address,
        user_agent=session.user_agent,
    )


def _current_session_to_read(session: AuthSession) -> CurrentSessionRead:
    return CurrentSessionRead(
        session_uuid=session.session_uuid,
        created_at=_as_utc(session.created_at),
        last_seen_at=_as_utc(session.last_seen_at),
        expires_at=_as_utc(session.expires_at),
        revoked_at=_as_utc(session.revoked_at),
        is_current=True,
        is_revoked=bool(session.is_revoked),
        ip_address=session.ip_address,
        user_agent=session.user_agent,
    )


async def _get_session_by_uuid(
    db: AsyncSession,
    *,
    session_uuid: str,
    user_id: int | None = None,
) -> AuthSession | None:
    stmt = select(AuthSession).where(AuthSession.session_uuid == session_uuid)
    if user_id is not None:
        stmt = stmt.where(AuthSession.user_id == user_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def _issue_tokens_for_session(
    db: AsyncSession,
    *,
    user: User,
    request: Request,
) -> tuple[AuthSession, str, str]:
    now = _utcnow()
    session_uuid = str(uuid4())
    refresh_jti = str(uuid4())

    expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    auth_session = AuthSession(
        user_id=user.id,
        session_uuid=session_uuid,
        refresh_jti=refresh_jti,
        ip_address=_client_ip(request),
        user_agent=_user_agent(request),
        created_at=now,
        last_seen_at=now,
        expires_at=expires_at,
        is_revoked=False,
        revoked_at=None,
    )
    db.add(auth_session)
    await db.flush()

    # FIX: Исправлены вызовы create_access_token и create_refresh_token
    access_token = create_access_token(
        subject=str(user.id),
        token_version=user.token_version,
        extra_claims={"sid": session_uuid},
    )
    refresh_token, _ = create_refresh_token(
        subject=str(user.id),
        token_version=user.token_version,
        session_id=session_uuid,
        refresh_jti=refresh_jti,
    )

    return auth_session, access_token, refresh_token


async def _revoke_session(
    db: AsyncSession,
    *,
    session: AuthSession,
    now: datetime | None = None,
) -> None:
    ts = _as_utc(now or _utcnow())
    session.is_revoked = True
    session.revoked_at = ts
    session.last_seen_at = ts
    await db.flush()


async def _revoke_all_other_sessions(
    db: AsyncSession,
    *,
    user_id: int,
    current_session_uuid: str,
    now: datetime | None = None,
) -> int:
    ts = _as_utc(now or _utcnow())
    result = await db.execute(
        update(AuthSession)
        .where(
            AuthSession.user_id == user_id,
            AuthSession.session_uuid != current_session_uuid,
            AuthSession.is_revoked.is_(False),
        )
        .values(
            is_revoked=True,
            revoked_at=ts,
            last_seen_at=ts,
        )
    )
    return int(result.rowcount or 0)


async def _fail_refresh(
    db: AsyncSession,
    *,
    request: Request,
    reason: str,
    user: User | None = None,
    session_id: str | None = None,
    detail: str = "Invalid refresh token",
) -> None:
    await log_event(
        db,
        action="refresh_failed",
        current_user=user,
        peer=None,
        resource=None,
        details={
            "reason": reason,
            "session_id": session_id,
        },
        request=request,
    )
    await db.commit()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/login", response_model=TokenRead)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(User).where(User.username == form_data.username)
    )
    user = result.scalar_one_or_none()

    if user is None or not verify_password(form_data.password, user.hashed_password):
        await log_event(
            db,
            action="login_failed",
            current_user=user,
            peer=None,
            resource=None,
            details={"reason": "invalid_credentials", "username": form_data.username},
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        await log_event(
            db,
            action="login_failed",
            current_user=user,
            peer=None,
            resource=None,
            details={"reason": "inactive_user"},
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )

    auth_session, access_token, refresh_token = await _issue_tokens_for_session(
        db,
        user=user,
        request=request,
    )

    # ИСПРАВЛЕНИЕ: добавлен username в details
    await log_event(
        db,
        action="login_success",
        current_user=user,
        peer=None,
        resource=None,
        details={
            "session_id": auth_session.session_uuid,
            "username": user.username,
        },
        request=request,
    )
    await db.commit()

    return TokenRead(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@router.post("/refresh", response_model=TokenRead)
async def refresh_access_token(
    payload: RefreshTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    decoded = decode_refresh_token(payload.refresh_token)
    if not decoded:
        await _fail_refresh(
            db,
            request=request,
            reason="invalid_refresh_token",
        )

    sub = decoded.get("sub")
    ver = decoded.get("ver")
    sid = decoded.get("sid")
    jti = decoded.get("jti")

    if sub is None or ver is None or not sid or not jti:
        await _fail_refresh(
            db,
            request=request,
            reason="malformed_refresh_token",
            session_id=sid,
        )

    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        await _fail_refresh(
            db,
            request=request,
            reason="invalid_refresh_subject",
            session_id=sid,
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        await _fail_refresh(
            db,
            request=request,
            reason="user_not_found_or_inactive",
            user=user,
            session_id=sid,
        )

    if user.token_version != ver:
        await _fail_refresh(
            db,
            request=request,
            reason="token_revoked",
            user=user,
            session_id=sid,
            detail="Refresh token has been revoked",
        )

    auth_session = await _get_session_by_uuid(
        db,
        session_uuid=sid,
        user_id=user.id,
    )
    if auth_session is None:
        await _fail_refresh(
            db,
            request=request,
            reason="session_not_found",
            user=user,
            session_id=sid,
        )

    now = _as_utc(_utcnow())
    expires_at = _as_utc(auth_session.expires_at)

    if auth_session.is_revoked:
        await _fail_refresh(
            db,
            request=request,
            reason="session_revoked",
            user=user,
            session_id=sid,
            detail="Refresh token has been revoked",
        )

    if expires_at is not None and expires_at <= now:
        await _revoke_session(db, session=auth_session, now=now)
        await _fail_refresh(
            db,
            request=request,
            reason="session_expired",
            user=user,
            session_id=sid,
            detail="Refresh token has expired",
        )

    if auth_session.refresh_jti != jti:
        await _revoke_session(db, session=auth_session, now=now)
        await log_event(
        db,
        action="refresh_token_reuse_detected",
        current_user=user,
        peer=None,
        resource=None,
        details={
            "session_id": sid,
            "reason": "refresh_token_reuse",
            "presented_jti": jti,
            "expected_jti": auth_session.refresh_jti,
        },
        request=request,
    )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    new_refresh_jti = str(uuid4())
    auth_session.refresh_jti = new_refresh_jti
    auth_session.last_seen_at = now
    auth_session.ip_address = _client_ip(request)
    auth_session.user_agent = _user_agent(request)

    # FIX: Исправлены вызовы create_access_token и create_refresh_token
    access_token = create_access_token(
        subject=str(user.id),
        token_version=user.token_version,
        extra_claims={"sid": auth_session.session_uuid},
    )
    refresh_token, _ = create_refresh_token(
        subject=str(user.id),
        token_version=user.token_version,
        session_id=auth_session.session_uuid,
        refresh_jti=new_refresh_jti,
    )

    await log_event(
        db,
        action="refresh_success",
        current_user=user,
        peer=None,
        resource=None,
        details={"session_id": auth_session.session_uuid},
        request=request,
    )
    await db.commit()

    return TokenRead(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    payload: RefreshTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    decoded = decode_refresh_token(payload.refresh_token)
    if not decoded:
        await log_event(
            db,
            action="logout_failed",
            current_user=None,
            peer=None,
            resource=None,
            details={"reason": "invalid_refresh_token"},
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    sid = decoded.get("sid")
    sub = decoded.get("sub")

    if not sid or sub is None:
        await log_event(
            db,
            action="logout_failed",
            current_user=None,
            peer=None,
            resource=None,
            details={"reason": "malformed_refresh_token"},
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        await log_event(
            db,
            action="logout_failed",
            current_user=None,
            peer=None,
            resource=None,
            details={"reason": "invalid_refresh_subject"},
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    auth_session = await _get_session_by_uuid(
        db,
        session_uuid=sid,
        user_id=user_id,
    )
    if auth_session is None:
        await log_event(
            db,
            action="logout_failed",
            current_user=user,
            peer=None,
            resource=None,
            details={"reason": "session_not_found", "session_id": sid},
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if auth_session.is_revoked:
        await log_event(
            db,
            action="logout_success",
            current_user=user,
            peer=None,
            resource=None,
            details={"session_id": sid, "already_revoked": True},
            request=request,
        )
        await db.commit()
        return {"detail": "Logged out"}

    await _revoke_session(db, session=auth_session)

    await log_event(
        db,
        action="logout_success",
        current_user=user,
        peer=None,
        resource=None,
        details={"session_id": sid, "reason": "refresh_token_reuse"},
        request=request,
    )
    await db.commit()

    return {"detail": "Logged out"}


@router.get("/me", response_model=UserRead)
async def read_me(
    current_user: User = Depends(get_current_user),
):
    return UserRead(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        is_active=current_user.is_active,
        is_admin=current_user.is_admin,
        token_version=current_user.token_version,
        created_at=_as_utc(current_user.created_at),
    )


@router.get("/sessions/current", response_model=CurrentSessionRead)
async def read_current_session(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header.split(" ", 1)[1].strip()
    try:
        decoded = decode_access_token(token)
    except JWTError:
        decoded = None

    if not decoded:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    sid = decoded.get("sid")
    if not sid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    auth_session = await _get_session_by_uuid(
        db,
        session_uuid=sid,
        user_id=current_user.id,
    )
    if auth_session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Current session not found",
        )

    return _current_session_to_read(auth_session)


@router.get("/sessions", response_model=SessionListRead)
async def list_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    current_sid = None
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        try:
            decoded = decode_access_token(token)
        except JWTError:
            decoded = None
        if decoded:
            current_sid = decoded.get("sid")

    result = await db.execute(
        select(AuthSession)
        .where(AuthSession.user_id == current_user.id)
        .order_by(AuthSession.created_at.desc())
    )
    sessions = result.scalars().all()

    items: list[SessionRead] = []
    for session in sessions:
        item = _session_to_read(session)
        item.is_current = session.session_uuid == current_sid
        items.append(item)

    return SessionListRead(items=items)


@router.delete("/sessions/others", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_other_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header.split(" ", 1)[1].strip()
    try:
        decoded = decode_access_token(token)
    except JWTError:
        decoded = None

    if not decoded or not decoded.get("sid"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    current_sid = decoded["sid"]
    revoked_count = await _revoke_all_other_sessions(
        db,
        user_id=current_user.id,
        current_session_uuid=current_sid,
    )

    await log_event(
        db,
        action="sessions_revoke_others",
        current_user=current_user,
        peer=None,
        resource=None,
        details={
            "session_id": current_sid,
            "revoked_count": revoked_count,
        },
        request=request,
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/sessions/{session_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_single_session(
    session_uuid: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    auth_header = request.headers.get("authorization", "")
    current_sid = None
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        try:
            decoded = decode_access_token(token)
        except JWTError:
            decoded = None
        if decoded:
            current_sid = decoded.get("sid")

    if current_sid == session_uuid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot revoke current session via this endpoint",
        )

    auth_session = await _get_session_by_uuid(
        db,
        session_uuid=session_uuid,
        user_id=current_user.id,
    )
    if auth_session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    if not auth_session.is_revoked:
        await _revoke_session(db, session=auth_session)

    await log_event(
        db,
        action="session_revoked",
        current_user=current_user,
        peer=None,
        resource=None,
        details={"session_id": session_uuid},
        request=request,
    )
    await db.commit()

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/sessions", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_all_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    now = _as_utc(_utcnow())

    await db.execute(
        update(AuthSession)
        .where(
            AuthSession.user_id == current_user.id,
            AuthSession.is_revoked.is_(False),
        )
        .values(
            is_revoked=True,
            revoked_at=now,
            last_seen_at=now,
        )
    )

    current_user.token_version = (current_user.token_version or 0) + 1

    await log_event(
        db,
        action="sessions_revoke_all",
        current_user=current_user,
        peer=None,
        resource=None,
        details={},
        request=request,
    )
    await db.commit()

    return Response(status_code=status.HTTP_204_NO_CONTENT)
