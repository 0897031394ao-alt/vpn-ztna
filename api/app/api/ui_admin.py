from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.user import User
from app.models.tenant import Tenant
from app.models.peer import Peer, ProvisioningStatus
from app.models.policy import Policy
from app.models.resource import Resource
from app.core.security import decode_access_token, create_access_token

templates = Jinja2Templates(directory="/app/app_ui/templates")

ui_admin_router = APIRouter(tags=["ui-admin"])


async def get_current_user_from_cookie(request: Request) -> User | None:
    raw_cookie = request.cookies.get("access_token")
    token = None
    if raw_cookie:
        token = raw_cookie[7:] if raw_cookie.startswith("Bearer ") else raw_cookie

    payload = decode_access_token(token)
    if not payload:
        return None

    subject = payload.get("sub")
    if not subject:
        return None

    try:
        user_id = int(subject)
    except (TypeError, ValueError):
        return None

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()


async def load_dashboard_summary() -> dict:
    async with AsyncSessionLocal() as db:
        total_users = await db.scalar(select(func.count()).select_from(User))
        active_users = await db.scalar(
            select(func.count()).select_from(User).where(User.is_active.is_(True))
        )
        admin_users = await db.scalar(
            select(func.count()).select_from(User).where(User.is_admin.is_(True))
        )

        peers_result = await db.execute(
            select(Peer.provisioning_status, func.count(Peer.id))
            .group_by(Peer.provisioning_status)
        )
        peer_counts = {status.value: 0 for status in ProvisioningStatus}
        for status, count in peers_result.all():
            peer_counts[status.value] = count

        total_resources = await db.scalar(
            select(func.count()).select_from(Resource).where(Resource.is_active.is_(True))
        )
        total_policies = await db.scalar(
            select(func.count()).select_from(Policy).where(Policy.is_active.is_(True))
        )
        total_tenants = await db.scalar(
            select(func.count()).select_from(Tenant)
        )

    return {
        "users": {
            "total": total_users or 0,
            "active": active_users or 0,
            "admins": admin_users or 0,
        },
        "peers": {
            "total": sum(peer_counts.values()),
            "provisioned": peer_counts.get("provisioned", 0),
            "pending": peer_counts.get("pending", 0),
            "error": peer_counts.get("error", 0),
            "removed": peer_counts.get("removed", 0),
        },
        "resources": {
            "total": total_resources or 0,
        },
        "policies": {
            "total": total_policies or 0,
        },
        "tenants": {
            "total": total_tenants or 0,
        },
    }


@ui_admin_router.get("/")
async def ui_root():
    return RedirectResponse(url="/dashboard", status_code=307)


@ui_admin_router.get("/dashboard", response_class=HTMLResponse)
async def ui_dashboard_page(request: Request):
    print("DEBUG: ui_dashboard_page called")
    current_user = await get_current_user_from_cookie(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=302)
    summary = await load_dashboard_summary()
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "active_page": "/dashboard",
            "current_user": current_user,
            "summary": summary,
        },
    )


@ui_admin_router.get("/tenants", response_class=HTMLResponse)
async def ui_tenants_page(request: Request):
    current_user = await get_current_user_from_cookie(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="tenants.html",
        context={"active_page": "tenants", "current_user": current_user},
    )


@ui_admin_router.get("/policies", response_class=HTMLResponse)
async def ui_policies_page(request: Request):
    current_user = await get_current_user_from_cookie(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=302)

    raw_group_id = request.query_params.get("group_id")
    group_id = int(raw_group_id) if raw_group_id and raw_group_id.isdigit() else None

    return templates.TemplateResponse(
        request=request,
        name="policies.html",
        context={
            "active_page": "policies",
            "current_user": current_user,
            "group_id": group_id,
        },
    )


@ui_admin_router.get("/resources", response_class=HTMLResponse)
async def ui_resources_page(request: Request):
    current_user = await get_current_user_from_cookie(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="resources.html",
        context={"active_page": "resources", "current_user": current_user},
    )


@ui_admin_router.get("/debug/check", response_class=HTMLResponse)
async def ui_debug_check_page(request: Request):
    current_user = await get_current_user_from_cookie(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="debug_check.html",
        context={"active_page": "/debug/check", "current_user": current_user},
    )


@ui_admin_router.get("/debug/peer", response_class=HTMLResponse)
async def ui_debug_peer_page(request: Request):
    current_user = await get_current_user_from_cookie(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="debug_peer.html",
        context={"active_page": "/debug/peer", "current_user": current_user},
    )


@ui_admin_router.get("/users/table-paginated", response_class=HTMLResponse)
async def ui_users_table_paginated(
    request: Request,
    status: str = "active",
    page: int = 1,
    limit: int = 20,
):
    from app.main import load_users_filtered
    users, filters = await load_users_filtered(status, page, limit)
    return templates.TemplateResponse(
        request=request,
        name="users_table_paginated.html",
        context={"users": users, "filters": filters},
    )
