from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.user import User
from app.core.security import verify_password, create_access_token

templates = Jinja2Templates(directory="/app/app_ui/templates")

ui_auth_router = APIRouter(tags=["ui-auth"])

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
    password = str(form.get("password", "")).strip()

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()

        if not user or not verify_password(password, user.hashed_password):
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": "Invalid username or password"},
                status_code=401,
            )

        if not user.is_active:
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": "Account is inactive"},
                status_code=403,
            )

        access_token = create_access_token(
            subject=str(user.id),
            token_version=user.token_version,
            extra_claims={"sid": "ui-session"},
        )

        response = RedirectResponse(url="/dashboard", status_code=303)
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=False,
            samesite="Lax",
            max_age=3600,
        )
        return response

@ui_auth_router.post("/logout")
async def ui_logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token", path="/")
    return response
