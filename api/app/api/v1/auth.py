from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select, update, desc
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps.auth import (
    get_current_active_user,
    get_current_admin,
    get_current_user,
)
from app.core.config import settings
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
)
from app.db.session import get_db
from app.models.auth_session import AuthSession
from app.models.user import User
from app.schemas.auth import (
    UserRegister,
    TokenRead,
    UserMeRead,
    RefreshTokenRequest,
    AuthSessionRead,
    AuthSessionListResponse,
    CurrentSessionResponse,
)
from app.services.audit_service import log_event
from user_agents import parse as parse_user_agent

router = APIRouter(prefix="/auth", tags=["auth"])


async def get_user_by_username(db: AsyncSession, username: str) -> User | None:
    result = await db.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_user_agent_details(user_agent: str | None) -> dict:
    if not user_agent:
        return {
            "device_type": "unknown",
            "device_family": None,
            "os_family": None,
            "browser_family": None,
            "is_bot": False,
        }

    ua = parse_user_agent(user_agent)

    if ua.is_bot:
        device_type = "bot"
    elif ua.is_mobile:
        device_type = "mobile"
    elif ua.is_tablet:
        device_type = "tablet"
    elif ua.is_pc:
        device_type = "pc"
    else:
        device_type = "other"

    return {
        "device_type": device_type,
        "device_family": ua.device.family,
        "os_family": ua.os.family,
        "browser_family": ua.browser.family,
        "is_bot": ua.is_bot,
    }


def _build_session_display_name(ua_details: dict) -> str:
    browser = ua_details.get("browser_family") or ""
    os = ua_details.get("os_family") or ""
    device_type = ua_details.get("device_type") or "other"
    is_bot = ua_details.get("is_bot", False)

    if is_bot:
        return f"Bot / crawler ({browser})" if browser and browser != "Other" else "Bot / crawler"

    if browser and browser != "Other" and os and os != "Other":
        return f"{browser} on {os}"

    if browser and browser != "Other":
        return browser

    if os and os != "Other":
        return f"Unknown browser on {os}"

    if device_type == "mobile":
        return "Mobile device"
    if device_type == "tablet":
        return "Tablet"
    if device_type == "pc":
        return "Desktop"

    return "Unknown device"


@router.post("/register", response_model=UserMeRead, status_code=201)
async def register_user(
    payload: UserRegister,
    db: AsyncSession = Depends(get_db),
):
    existing_username = await get_user_by_username(db, payload.username)
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already registered",
        )

    existing_email = await get_user_by_email(db, payload.email)
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        is_active=True,
        is_admin=False,
    )

    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/login", response_model=TokenRead)
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    user = await get_user_by_username(db, form_data.username)
    if not user:
        await log_event(
            db,
            action="login_failed",
            current_user=None,
            peer=None,
            resource=None,
            details={"username": form_data.username, "reason": "user_not_found"},
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(form_data.password, user.hashed_password):
        await log_event(
            db,
            action="login_failed",
            current_user=user,
            peer=None,
            resource=None,
            details={"username": form_data.username, "reason": "bad_password"},
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
            details={"username": form_data.username, "reason": "inactive_user"},
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )

    session_expires_at = _utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    auth_session = AuthSession(
        user_id=user.id,
        refresh_jti="pending",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        is_revoked=False,
        expires_at=session_expires_at,
        last_seen_at=_utcnow(),
    )
    db.add(auth_session)
    await db.flush()

    access_token = create_access_token(
        subject=str(user.id),
        token_version=user.token_version,
        expires_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        extra_claims={"sid": auth_session.session_uuid},
    )

    refresh_token, refresh_jti = create_refresh_token(
        subject=str(user.id),
        token_version=user.token_version,
        session_id=auth_session.session_uuid,
        expires_days=settings.REFRESH_TOKEN_EXPIRE_DAYS,
    )

    auth_session.refresh_jti = refresh_jti

    await log_event(
        db,
        action="login_success",
        current_user=user,
        peer=None,
        resource=None,
        details={"username": form_data.username, "session_id": auth_session.session_uuid},
        request=request,
    )
    await db.commit()

    return TokenRead(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/refresh", response_model=TokenRead)
async def refresh_access_token(
    payload: RefreshTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    decoded = decode_refresh_token(payload.refresh_token)
    if not decoded:
        await log_event(
            db,
            action="refresh_failed",
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

    sub = decoded.get("sub")
    ver = decoded.get("ver")
    sid = decoded.get("sid")
    jti = decoded.get("jti")

    if sub is None or ver is None or not sid or not jti:
        await log_event(
            db,
            action="refresh_failed",
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
    except ValueError:
        await log_event(
            db,
            action="refresh_failed",
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
    if user is None or not user.is_active:
        await log_event(
            db,
            action="refresh_failed",
            current_user=user,
            peer=None,
            resource=None,
            details={"reason": "user_not_found_or_inactive", "session_id": sid},
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.token_version != ver:
        await log_event(
            db,
            action="refresh_failed",
            current_user=user,
            peer=None,
            resource=None,
            details={"reason": "token_revoked", "session_id": sid},
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    session_result = await db.execute(
        select(AuthSession).where(
            AuthSession.session_uuid == sid,
            AuthSession.user_id == user.id,
        )
    )
    auth_session = session_result.scalar_one_or_none()

    if auth_session is None:
        await log_event(
            db,
            action="refresh_failed",
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

    now = _utcnow()

    if auth_session.is_revoked:
        await log_event(
            db,
            action="refresh_failed",
            current_user=user,
            peer=None,
            resource=None,
            details={"reason": "session_revoked", "session_id": sid},
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if auth_session.expires_at <= now:
        auth_session.is_revoked = True
        auth_session.revoked_at = now
        await log_event(
            db,
            action="refresh_failed",
            current_user=user,
            peer=None,
            resource=None,
            details={"reason": "session_expired", "session_id": sid},
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if auth_session.refresh_jti != jti:
        auth_session.is_revoked = True
        auth_session.revoked_at = now
        await log_event(
            db,
            action="refresh_reuse_detected",
            current_user=user,
            peer=None,
            resource=None,
            details={
                "reason": "refresh_token_reuse",
                "session_id": sid,
                "presented_jti": jti,
                "expected_jti": auth_session.refresh_jti,
            },
            request=request,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    new_access_token = create_access_token(
        subject=str(user.id),
        token_version=user.token_version,
        expires_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        extra_claims={"sid": auth_session.session_uuid},
    )

    new_refresh_token, new_refresh_jti = create_refresh_token(
        subject=str(user.id),
        token_version=user.token_version,
        session_id=auth_session.session_uuid,
        expires_days=settings.REFRESH_TOKEN_EXPIRE_DAYS,
    )

    auth_session.refresh_jti = new_refresh_jti
    auth_session.last_seen_at = now
    auth_session.ip_address = request.client.host if request.client else auth_session.ip_address
    auth_session.user_agent = request.headers.get("user-agent") or auth_session.user_agent

    await log_event(
        db,
        action="refresh_success",
        current_user=user,
        peer=None,
        resource=None,
        details={"session_id": sid},
        request=request,
    )
    await db.commit()

    return TokenRead(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
    )


@router.post("/logout")
async def logout_current_session(
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

    sub = decoded.get("sub")
    sid = decoded.get("sid")

    if sub is None or sid is None:
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
    except ValueError:
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

    session_result = await db.execute(
        select(AuthSession).where(
            AuthSession.session_uuid == sid,
            AuthSession.user_id == user_id,
        )
    )
    auth_session = session_result.scalar_one_or_none()

    if auth_session:
        auth_session.is_revoked = True
        auth_session.revoked_at = _utcnow()
        auth_session.last_seen_at = _utcnow()

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    await log_event(
        db,
        action="logout",
        current_user=user,
        peer=None,
        resource=None,
        details={"session_id": sid},
        request=request,
    )
    await db.commit()

    return {"detail": "Session revoked"}


@router.post("/logout_all")
async def logout_all_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    current_user.token_version += 1

    await db.execute(
        update(AuthSession)
        .where(
            AuthSession.user_id == current_user.id,
            AuthSession.is_revoked.is_(False),
        )
        .values(
            is_revoked=True,
            revoked_at=_utcnow(),
            last_seen_at=_utcnow(),
        )
    )

    await log_event(
        db,
        action="logout_all",
        current_user=current_user,
        peer=None,
        resource=None,
        details={"token_version": current_user.token_version},
        request=request,
    )
    await db.commit()
    await db.refresh(current_user)

    return {"detail": "All sessions revoked"}


@router.get("/sessions", response_model=AuthSessionListResponse)
async def list_auth_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AuthSession)
        .where(AuthSession.user_id == current_user.id)
        .order_by(
            AuthSession.is_revoked.asc(),
            desc(AuthSession.last_seen_at),
            desc(AuthSession.created_at),
        )
    )
    sessions = result.scalars().all()

    current_sid = getattr(request.state, "session_uuid", None)
    sessions = sorted(
        sessions,
        key=lambda s: (
            s.session_uuid != current_sid,   # current first
            s.is_revoked,                    # active before revoked
            -(s.last_seen_at or s.created_at).timestamp(),  # newest first
        ),
    )

    items = []
    for session in sessions:
        ua_details = _parse_user_agent_details(session.user_agent)
        display_name = _build_session_display_name(ua_details)

        items.append(
            AuthSessionRead(
                session_uuid=session.session_uuid,
                ip_address=session.ip_address,
                user_agent=session.user_agent,
                is_revoked=session.is_revoked,
                expires_at=session.expires_at,
                last_seen_at=session.last_seen_at,
                created_at=session.created_at,
                revoked_at=session.revoked_at,
                is_current=(session.session_uuid == current_sid),
                display_name=display_name,
                device_type=ua_details["device_type"],
                device_family=ua_details["device_family"],
                os_family=ua_details["os_family"],
                browser_family=ua_details["browser_family"],
                is_bot=ua_details["is_bot"],
            )
        )

    return AuthSessionListResponse(items=items)


@router.delete("/sessions/others")
async def revoke_other_auth_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    current_sid = getattr(request.state, "session_uuid", None)
    now = _utcnow()

    stmt = (
        update(AuthSession)
        .where(
            AuthSession.user_id == current_user.id,
            AuthSession.is_revoked.is_(False),
        )
    )

    if current_sid:
        stmt = stmt.where(AuthSession.session_uuid != current_sid)

    stmt = stmt.values(
        is_revoked=True,
        revoked_at=now,
        last_seen_at=now,
    )

    await db.execute(stmt)

    await log_event(
        db,
        action="other_sessions_revoked",
        current_user=current_user,
        peer=None,
        resource=None,
        details={"current_session_id": current_sid},
        request=request,
    )
    await db.commit()

    return {"detail": "Other sessions revoked"}


@router.delete("/sessions/{session_uuid}")
async def revoke_auth_session(
    session_uuid: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AuthSession).where(
            AuthSession.session_uuid == session_uuid,
            AuthSession.user_id == current_user.id,
        )
    )
    auth_session = result.scalar_one_or_none()

    if auth_session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    if not auth_session.is_revoked:
        auth_session.is_revoked = True
        auth_session.revoked_at = _utcnow()
        auth_session.last_seen_at = _utcnow()

    await log_event(
        db,
        action="session_revoked",
        current_user=current_user,
        peer=None,
        resource=None,
        details={"session_id": auth_session.session_uuid},
        request=request,
    )
    await db.commit()

    return {"detail": "Session revoked"}


@router.get("/me", response_model=UserMeRead)
async def read_users_me(
    current_user: User = Depends(get_current_active_user),
):
    return current_user


@router.get("/session/current", response_model=CurrentSessionResponse)
async def get_current_session(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    current_sid = getattr(request.state, "session_uuid", None)
    if not current_sid:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Current session not found",
        )

    result = await db.execute(
        select(AuthSession).where(
            AuthSession.session_uuid == current_sid,
            AuthSession.user_id == current_user.id,
        )
    )
    auth_session = result.scalar_one_or_none()

    if auth_session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Current session not found",
        )

    ua_details = _parse_user_agent_details(auth_session.user_agent)
    display_name = _build_session_display_name(ua_details)

    return CurrentSessionResponse(
        user=UserMeRead.model_validate(current_user),
        session=AuthSessionRead(
            session_uuid=auth_session.session_uuid,
            ip_address=auth_session.ip_address,
            user_agent=auth_session.user_agent,
            is_revoked=auth_session.is_revoked,
            expires_at=auth_session.expires_at,
            last_seen_at=auth_session.last_seen_at,
            created_at=auth_session.created_at,
            revoked_at=auth_session.revoked_at,
            is_current=True,
            display_name=display_name,
            device_type=ua_details["device_type"],
            device_family=ua_details["device_family"],
            os_family=ua_details["os_family"],
            browser_family=ua_details["browser_family"],
            is_bot=ua_details["is_bot"],
        ),
    )
