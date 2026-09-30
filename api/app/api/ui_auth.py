import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import (
    create_access_token,
    decode_access_token,
    verify_password,
)
from app.db.session import AsyncSessionLocal
from app.models.auth_session import AuthSession
from app.models.user import User
from app.services.audit import log_event


templates = Jinja2Templates(directory="/app/app_ui/templates")
ui_auth_router = APIRouter(tags=["ui-auth"])


def _cookie_secure() -> bool:
    value = os.getenv("UI_COOKIE_SECURE", "false")
    return value.strip().lower() in {"1", "true", "yes", "on"}


async def _safe_audit(
    db: AsyncSession,
    *,
    action: str,
    current_user: User | None = None,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
) -> None:
    try:
        await log_event(
            db,
            action=action,
            current_user=current_user,
            details=details,
            request=request,
        )
        await db.commit()
    except Exception:
        await db.rollback()


@ui_auth_router.get("/login", response_class=HTMLResponse)
async def ui_login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={},
    )


@ui_auth_router.post("/login", response_class=HTMLResponse)
async def ui_login_submit(request: Request):
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))

    async with AsyncSessionLocal() as db:
        user = await db.scalar(
            select(User).where(User.username == username)
        )

        if user is None or not verify_password(
            password,
            user.hashed_password,
        ):
            await _safe_audit(
                db,
                action="ui.login.failed",
                current_user=user if user else None,
                details={
                    "reason": "invalid_credentials",
                    "username": username,
                },
                request=request,
            )
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": "Invalid username or password"},
                status_code=401,
            )

        if not user.is_active:
            await _safe_audit(
                db,
                action="ui.login.failed",
                current_user=user,
                details={
                    "reason": "inactive_user",
                    "username": user.username,
                },
                request=request,
            )
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": "Account is inactive"},
                status_code=403,
            )

        if not user.is_admin:
            await _safe_audit(
                db,
                action="ui.login.failed",
                current_user=user,
                details={
                    "reason": "admin_required",
                    "username": user.username,
                },
                request=request,
            )
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": "Admin privileges required"},
                status_code=403,
            )

        now = datetime.now(timezone.utc)
        expires_minutes = int(settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        session_uuid = str(uuid4())

        auth_session = AuthSession(
            user_id=user.id,
            session_uuid=session_uuid,
            refresh_jti=str(uuid4()),
            ip_address=(
                request.client.host
                if request.client and request.client.host
                else None
            ),
            user_agent=request.headers.get("user-agent"),
            is_revoked=False,
            expires_at=now + timedelta(minutes=expires_minutes),
            last_seen_at=now,
        )
        db.add(auth_session)
        await db.flush()

        access_token = create_access_token(
            subject=str(user.id),
            token_version=user.token_version,
            expires_minutes=expires_minutes,
            extra_claims={"sid": session_uuid},
        )

        await db.commit()

        await _safe_audit(
            db,
            action="ui.login.success",
            current_user=user,
            details={
                "username": user.username,
                "session_id": session_uuid,
            },
            request=request,
        )

    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="access_token",
        value=access_token,
        max_age=expires_minutes * 60,
        path="/",
        secure=_cookie_secure(),
        httponly=True,
        samesite="lax",
    )
    return response


@ui_auth_router.post("/logout")
async def ui_logout(request: Request):
    raw_cookie = request.cookies.get("access_token")
    token = raw_cookie.strip() if raw_cookie else ""

    if token.startswith("Bearer "):
        token = token[len("Bearer "):].strip()

    payload = decode_access_token(token)
    session_uuid = (
        str(payload.get("sid") or "").strip()
        if payload
        else ""
    )

    if session_uuid:
        async with AsyncSessionLocal() as db:
            auth_session = await db.scalar(
                select(AuthSession).where(
                    AuthSession.session_uuid == session_uuid
                )
            )
            if auth_session is not None:
                user = await db.get(User, auth_session.user_id)
            else:
                user = None

            if auth_session is not None and not auth_session.is_revoked:
                now = datetime.now(timezone.utc)
                auth_session.is_revoked = True
                auth_session.revoked_at = now
                auth_session.last_seen_at = now
                await db.commit()

                await _safe_audit(
                    db,
                    action="ui.logout.success",
                    current_user=user,
                    details={
                        "session_id": session_uuid,
                    },
                    request=request,
                )
            else:
                await _safe_audit(
                    db,
                    action="ui.logout.failed",
                    current_user=user,
                    details={
                        "reason": "session_not_found_or_already_revoked",
                        "session_id": session_uuid,
                    },
                    request=request,
                )
    else:
        async with AsyncSessionLocal() as db:
            await _safe_audit(
                db,
                action="ui.logout.failed",
                current_user=None,
                details={
                    "reason": "missing_or_invalid_access_token",
                },
                request=request,
            )

    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(
        key="access_token",
        path="/",
        secure=_cookie_secure(),
        httponly=True,
        samesite="lax",
    )
    return response

