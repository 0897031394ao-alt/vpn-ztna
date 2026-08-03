from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List
from sqlalchemy import select, func
from sqlalchemy import text

import logging

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import generate_latest, REGISTRY

from app.api.ui_admin import ui_admin_router, get_current_user_from_cookie, load_dashboard_summary
from app.api.ui_admin_fragments import ui_fragments_router
from app.api.ui_auth import ui_auth_router
from app.api.v1.router import api_router
from app.api.v1.audit import router as audit_router
from app.api.ui_policy_explain import router as ui_policy_explain_router
from app.core.limiter import limiter
from app.db.base import Base  # noqa: F401
from app.db.session import AsyncSessionLocal
from app.services.access_explain_service import (
    explain_user_access,
    explain_peer_access,
    explain_user_resource_access,
)
from app.models.peer import Peer, ProvisioningStatus
from app.models.resource import Resource
from app.models.user import User
from app.services.peer_service import (
    recalculate_peer_by_id,
    provision_peer_by_id,
    remove_peer_by_id,
    regenerate_peer_keys,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="VPN-ZTNA API", version="0.1.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

BASE_DIR = Path(__file__).resolve().parent.parent
UI_DIR = BASE_DIR / "app_ui"

app.include_router(api_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")
app.include_router(ui_policy_explain_router)
app.include_router(ui_auth_router)
app.include_router(ui_admin_router)
app.include_router(ui_fragments_router)

app.mount("/static", StaticFiles(directory=str(UI_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(UI_DIR / "templates"))

Instrumentator().instrument(app).expose(app)


# ---------------------------------------------------------------------------
# Health / Ready
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> Dict[str, Any]:
    return {"status": "ok", "version": "0.1.0"}


@app.get("/ready")
async def ready():
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    return {
        "status": "ready" if db_ok else "unhealthy",
        "database": "ok" if db_ok else "failed",
    }


# ---------------------------------------------------------------------------
# Dashboard / Logout (дублируют ui_admin_router но нужны с current_user)
# ---------------------------------------------------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
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


@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response


# ---------------------------------------------------------------------------
# Debug pages
# ---------------------------------------------------------------------------

@app.get("/debug/access", response_class=HTMLResponse)
async def ui_debug_access_page(request: Request):
    current_user = await get_current_user_from_cookie(request)
    return templates.TemplateResponse(
        request=request,
        name="debug_access.html",
        context={
            "active_page": "/debug/access",
            "current_user": current_user,
        },
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def load_peers_filtered(
    status: str = "all",
    hide_removed: int = 1,
) -> tuple[List[Dict[str, Any]], dict]:
    valid_statuses = {"all"} | {s.value for s in ProvisioningStatus}
    if status not in valid_statuses:
        status = "all"

    hide_removed_enabled = bool(hide_removed)

    async with AsyncSessionLocal() as db:
        stmt = select(Peer)
        if status != "all":
            stmt = stmt.where(Peer.provisioning_status == ProvisioningStatus(status))
        if hide_removed_enabled and status != "removed":
            stmt = stmt.where(Peer.provisioning_status != ProvisioningStatus.removed)
        stmt = stmt.order_by(Peer.id.asc())
        result = await db.execute(stmt)
        peer_rows = result.scalars().all()

    peers: List[Dict[str, Any]] = [
        {
            "id": peer.id,
            "user_id": peer.user_id,
            "vpn_ip": peer.vpn_ip,
            "allowed_ips": peer.allowed_ips,
            "provisioning_status": peer.provisioning_status,
            "public_key": peer.public_key,
            "provisioning_error": peer.provisioning_error,
        }
        for peer in peer_rows
    ]

    filters = {
        "status": status,
        "hide_removed": hide_removed_enabled,
    }

    return peers, filters


async def load_active_users() -> list[dict]:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(User)
            .where(User.is_active == True)  # noqa: E712
            .order_by(User.username.asc())
        )
        users = result.scalars().all()
    return [
        {"id": user.id, "label": f"{user.username} ({user.email})"}
        for user in users
    ]


async def load_active_peers() -> list[dict]:
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Peer).order_by(Peer.id.asc()))
        peers = result.scalars().all()

        user_ids = {p.user_id for p in peers if p.user_id is not None}
        users_map: dict[int, User] = {}
        if user_ids:
            users_result = await db.execute(select(User).where(User.id.in_(user_ids)))
            for user in users_result.scalars().all():
                users_map[user.id] = user

    items = []
    for peer in peers:
        user_label = f"user #{peer.user_id}"
        if peer.user_id in users_map:
            u = users_map[peer.user_id]
            user_label = f"{u.username} ({u.email})"
        items.append({
            "id": peer.id,
            "public_key": peer.public_key,
            "provisioning_error": peer.provisioning_error,
            "vpn_ip": peer.vpn_ip,
            "allowed_ips": peer.allowed_ips,
            "provisioning_status": (
                peer.provisioning_status.value
                if hasattr(peer.provisioning_status, "value")
                else str(peer.provisioning_status)
            ),
            "user_id": peer.user_id,
            "user_label": user_label,
        })
    return items


async def load_debug_check_options() -> dict:
    async with AsyncSessionLocal() as db:
        users_result = await db.execute(
            select(User).where(User.is_active == True).order_by(User.username.asc())  # noqa: E712
        )
        resources_result = await db.execute(
            select(Resource).where(Resource.is_active == True).order_by(Resource.name.asc())  # noqa: E712
        )
        users = users_result.scalars().all()
        resources = resources_result.scalars().all()

    return {
        "users": [
            {"id": u.id, "label": f"{u.username} ({u.email})"}
            for u in users
        ],
        "resources": [
            {
                "id": r.id,
                "label": f"{r.name} ({r.resource_type.value if hasattr(r.resource_type, 'value') else str(r.resource_type)})",
            }
            for r in resources
        ],
    }


# ---------------------------------------------------------------------------
# Peer actions
# ---------------------------------------------------------------------------

@app.post("/ui/peers/{peer_id}/recalculate", response_class=HTMLResponse)
async def ui_peers_recalculate(
    peer_id: int,
    request: Request,
    status: str = "all",
    hide_removed: int = 1,
):
    async with AsyncSessionLocal() as db:
        await recalculate_peer_by_id(db, peer_id)
    peers, filters = await load_peers_filtered(status, hide_removed)
    return templates.TemplateResponse(
        request=request,
        name="peers_table.html",
        context={
            "peers": peers,
            "page": filters.get("page", 1),
            "pagesize": filters.get("pagesize", 10),
            "status": filters.get("status", status),
            "hide_removed": filters.get("hide_removed", hide_removed),
            "total": filters.get("total", len(peers)),
            "total_pages": filters.get("total_pages", 1),
            "filters": filters,
        }
    )


@app.post("/ui/peers/{peer_id}/provision", response_class=HTMLResponse)
async def ui_peers_provision(
    peer_id: int,
    request: Request,
    status: str = "all",
    hide_removed: int = 1,
):
    async with AsyncSessionLocal() as db:
        await provision_peer_by_id(db, peer_id)
    peers, filters = await load_peers_filtered(status, hide_removed)
    return templates.TemplateResponse(
        request=request,
        name="peers_table.html",
        context={
            "peers": peers,
            "page": filters.get("page", 1),
            "pagesize": filters.get("pagesize", 10),
            "status": filters.get("status", status),
            "hide_removed": filters.get("hide_removed", hide_removed),
            "total": filters.get("total", len(peers)),
            "total_pages": filters.get("total_pages", 1),
            "filters": filters,
        }
    )


@app.post("/ui/peers/{peer_id}/retry", response_class=HTMLResponse)
async def ui_peers_retry(
    peer_id: int,
    request: Request,
    status: str = "all",
    hide_removed: int = 1,
):
    async with AsyncSessionLocal() as db:
        await provision_peer_by_id(db, peer_id)
    peers, filters = await load_peers_filtered(status, hide_removed)
    return templates.TemplateResponse(
        request=request,
        name="peers_table.html",
        context={
            "peers": peers,
            "page": filters.get("page", 1),
            "pagesize": filters.get("pagesize", 10),
            "status": filters.get("status", status),
            "hide_removed": filters.get("hide_removed", hide_removed),
            "total": filters.get("total", len(peers)),
            "total_pages": filters.get("total_pages", 1),
            "filters": filters,
        }
    )


@app.delete("/ui/peers/{peer_id}", response_class=HTMLResponse)
async def ui_peers_remove(
    peer_id: int,
    request: Request,
    status: str = "all",
    hide_removed: int = 1,
):
    async with AsyncSessionLocal() as db:
        await remove_peer_by_id(db, peer_id)
    peers, filters = await load_peers_filtered(status, hide_removed)
    return templates.TemplateResponse(
        request=request,
        name="peers_table.html",
        context={
            "peers": peers,
            "page": filters.get("page", 1),
            "pagesize": filters.get("pagesize", 10),
            "status": filters.get("status", status),
            "hide_removed": filters.get("hide_removed", hide_removed),
            "total": filters.get("total", len(peers)),
            "total_pages": filters.get("total_pages", 1),
            "filters": filters,
        }
    )


@app.post("/ui/peers/{peer_id}/revoke")
async def ui_peer_revoke(peer_id: int):
    async with AsyncSessionLocal() as db:
        peer = await db.get(Peer, peer_id)
        if not peer:
            return PlainTextResponse("Peer not found.\n", status_code=404)
        if peer.provisioning_status in (
            ProvisioningStatus.pending_revoke,
            ProvisioningStatus.removed,
        ):
            return Response(status_code=200, headers={"HX-Refresh": "true"})
        if not peer.public_key:
            return PlainTextResponse(
                "Peer has no public key, cannot schedule revoke.\n",
                status_code=400,
            )
        peer.provisioning_status = ProvisioningStatus.pending_revoke
        peer.provisioning_error = "Waiting for provisioning agent to revoke peer"
        await db.commit()
    return Response(status_code=200, headers={"HX-Refresh": "true"})


@app.post("/ui/peers/{peer_id}/regenerate")
async def ui_peer_regenerate(peer_id: int):
    async with AsyncSessionLocal() as db:
        try:
            await regenerate_peer_keys(db, peer_id)
        except HTTPException as e:
            return PlainTextResponse(str(e.detail), status_code=e.status_code)
    return Response(status_code=200, headers={"HX-Refresh": "true"})


@app.post("/ui/peers/sync-all", response_class=HTMLResponse)
async def ui_peers_sync_all(
    request: Request,
    status: str = "all",
    hide_removed: int = 1,
):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Peer.id)
            .where(Peer.provisioning_status == ProvisioningStatus.pending)
            .order_by(Peer.id.asc())
        )
        pending_ids = list(result.scalars().all())

    errors = []
    for pid in pending_ids:
        try:
            async with AsyncSessionLocal() as db:
                await provision_peer_by_id(db, pid)
        except Exception as e:
            errors.append(f"peer_id={pid}: {e}")

    peers, filters = await load_peers_filtered(status, hide_removed)
    return templates.TemplateResponse(
        request=request,
        name="peers_table.html",
        context={
            "peers": peers,
            "page": filters.get("page", 1),
            "pagesize": filters.get("pagesize", 10),
            "status": filters.get("status", status),
            "hide_removed": filters.get("hide_removed", hide_removed),
            "total": filters.get("total", len(peers)),
            "total_pages": filters.get("total_pages", 1),
            "filters": filters,
            "sync_result": {"processed": len(pending_ids), "errors": errors},
        }
    )


@app.post("/ui/peers/retry-errors", response_class=HTMLResponse)
async def ui_peers_retry_errors(
    request: Request,
    status: str = "all",
    hide_removed: int = 1,
):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Peer.id)
            .where(Peer.provisioning_status == ProvisioningStatus.error)
            .order_by(Peer.id.asc())
        )
        error_ids = list(result.scalars().all())

    errors = []
    for pid in error_ids:
        try:
            async with AsyncSessionLocal() as db:
                await provision_peer_by_id(db, pid)
        except Exception as e:
            errors.append(f"peer_id={pid}: {e}")

    peers, filters = await load_peers_filtered(status, hide_removed)
    return templates.TemplateResponse(
        request=request,
        name="peers_table.html",
        context={
            "peers": peers,
            "page": filters.get("page", 1),
            "pagesize": filters.get("pagesize", 10),
            "status": filters.get("status", status),
            "hide_removed": filters.get("hide_removed", hide_removed),
            "total": filters.get("total", len(peers)),
            "total_pages": filters.get("total_pages", 1),
            "filters": filters,
            "sync_result": {"processed": len(error_ids), "errors": errors},
        },
    )


# ---------------------------------------------------------------------------
# Users toggle (HTMX actions из таблицы)
# ---------------------------------------------------------------------------

@app.post("/ui/users/{user_id}/toggle-active", response_class=HTMLResponse)
async def ui_users_toggle_active(
    user_id: int,
    request: Request,
    status: str = "active",
):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if user:
            user.is_active = not user.is_active
            await db.commit()
    users_rows, filters = await _load_users_for_table(status)
    return templates.TemplateResponse(
        request=request,
        name="users_table.html",
        context={"users": users_rows, "filters": filters},
    )


@app.post("/ui/users/{user_id}/toggle-admin", response_class=HTMLResponse)
async def ui_users_toggle_admin(
    user_id: int,
    request: Request,
    status: str = "active",
):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if user:
            user.is_admin = not user.is_admin
            await db.commit()
    users_rows, filters = await _load_users_for_table(status)
    return templates.TemplateResponse(
        request=request,
        name="users_table.html",
        context={"users": users_rows, "filters": filters},
    )


async def _load_users_for_table(
    status: str = "active",
) -> tuple[list[dict], dict]:
    valid_statuses = {"all", "active", "inactive"}
    if status not in valid_statuses:
        status = "active"

    async with AsyncSessionLocal() as db:
        stmt = select(User)
        if status == "active":
            stmt = stmt.where(User.is_active == True)  # noqa: E712
        elif status == "inactive":
            stmt = stmt.where(User.is_active == False)  # noqa: E712
        stmt = stmt.order_by(User.id.asc())
        result = await db.execute(stmt)
        user_rows = result.scalars().all()

    users = [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "is_active": u.is_active,
            "is_admin": u.is_admin,
            "created_at": u.created_at,
        }
        for u in user_rows
    ]
    filters = {"status": status}
    return users, filters


# ---------------------------------------------------------------------------
# Debug HTMX fragments
# ---------------------------------------------------------------------------

@app.get("/ui/debug/access/form", response_class=HTMLResponse)
async def ui_debug_access_form(request: Request):
    options = await load_debug_check_options()
    return templates.TemplateResponse(
        request=request,
        name="debug_access_form.html",
        context=options,
    )


@app.get("/ui/debug/check/form", response_class=HTMLResponse)
async def ui_debug_check_form(request: Request):
    options = await load_debug_check_options()
    return templates.TemplateResponse(
        request=request,
        name="debug_check_form.html",
        context=options,
    )


@app.get("/ui/debug/check/result", response_class=HTMLResponse)
async def ui_debug_check_result(
    request: Request,
    user_id: int,
    resource_id: int,
):
    async with AsyncSessionLocal() as db:
        result = await explain_user_resource_access(db, user_id, resource_id)
    return templates.TemplateResponse(
        request=request,
        name="debug_check_result.html",
        context=result,
    )


@app.get("/ui/debug/access/result", response_class=HTMLResponse)
async def ui_debug_access_result(
    request: Request,
    user_id: int,
):
    async with AsyncSessionLocal() as db:
        result = await explain_user_access(db, user_id)
    return templates.TemplateResponse(
        request=request,
        name="debug_access_result.html",
        context=result,
    )


@app.get("/ui/debug/peer/form", response_class=HTMLResponse)
async def ui_debug_peer_form(request: Request):
    peers = await load_active_peers()
    return templates.TemplateResponse(
        request=request,
        name="debug_peer_form.html",
        context={"peers": peers},
    )


@app.get("/ui/debug/peer/result", response_class=HTMLResponse)
async def ui_debug_peer_result(request: Request, peer_id: int):
    async with AsyncSessionLocal() as db:
        result = await explain_peer_access(db, peer_id)
    return templates.TemplateResponse(
        request=request,
        name="debug_peer_result.html",
        context=result,
    )


@app.get("/users", response_class=HTMLResponse)
async def ui_users_page(request: Request):
    current_user = await get_current_user_from_cookie(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="users.html",
        context={
            "active_page": "/users",
            "current_user": current_user,
        },
    )
