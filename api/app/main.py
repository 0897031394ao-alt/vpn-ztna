from contextlib import asynccontextmanager
from pathlib import Path
from pydantic import ValidationError
from typing import Any, Dict, List
from uuid import UUID
from sqlalchemy import select
import httpx
from fastapi import APIRouter, FastAPI, Form, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.v1.router import api_router
from app.api.ui_policy_explain import router as ui_policy_explain_router
from app.db.base import Base  # noqa: F401
from app.db.session import AsyncSessionLocal

from app.models.peer import Peer
from app.models.policy import Policy
from app.models.resource import Resource
from app.models.user import User
from app.models.group import Group, user_group
from app.schemas.resource import ResourceCreate, ResourceUpdate
from app.services.resource_service import (
    create_resource as create_resource_service,
    update_resource as update_resource_service,
    soft_delete_resource,
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="VPN-ZTNA API", version="0.1.0", lifespan=lifespan)

BASE_DIR = Path(__file__).resolve().parent.parent
UI_DIR = BASE_DIR / "app_ui"

app.include_router(api_router, prefix="/api/v1")
from app.api.v1.audit import router as audit_router
app.include_router(audit_router, prefix="/api/v1")
app.include_router(ui_policy_explain_router)

app.mount("/static", StaticFiles(directory=str(UI_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(UI_DIR / "templates"))


@app.get("/", response_class=HTMLResponse)
async def ui_index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={},
    )


@app.get("/tenants", response_class=HTMLResponse)
async def ui_tenants_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="tenants.html",
        context={},
    )


@app.get("/policies", response_class=HTMLResponse)
async def ui_policies_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="policies.html",
        context={},
    )


@app.get("/resources", response_class=HTMLResponse)
async def ui_resources_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="resources.html",
        context={},
    )


@app.get("/debug/access", response_class=HTMLResponse)
async def ui_debug_access_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="debug_access.html",
        context={},
    )


@app.get("/debug/check", response_class=HTMLResponse)
async def ui_debug_check_page(
    request: Request,
    user_id: int | None = None,
    resource_id: int | None = None,
):
    return templates.TemplateResponse(
        request=request,
        name="debug_check.html",
        context={
            "prefill_user_id": user_id,
            "prefill_resource_id": resource_id,
        },
    )


@app.get("/debug/peer", response_class=HTMLResponse)
async def ui_debug_peer_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="debug_peer.html",
        context={},
    )


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {"status": "ok", "version": "0.1.0"}


ui_router = APIRouter(prefix="/ui", tags=["ui"])


@ui_router.get("/peers/table", response_class=HTMLResponse)
async def ui_peers_table(request: Request):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Peer).order_by(Peer.id.asc()))
        peer_rows = result.scalars().all()

    peers: List[Dict[str, Any]] = []
    for peer in peer_rows:
        peers.append({
            "id": peer.id,
            "user_id": peer.user_id,
            "vpn_ip": peer.vpn_ip,
            "allowed_ips": peer.allowed_ips,
            "provisioning_status": peer.provisioning_status,
            "public_key": peer.public_key,
        })

    return templates.TemplateResponse(
        request=request,
        name="peers_table.html",
        context={"peers": peers},
    )


@ui_router.get("/resources/table", response_class=HTMLResponse)
async def ui_resources_table(request: Request):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Resource)
            .where(Resource.is_active == True)  # noqa: E712
            .order_by(Resource.id.asc())
        )
        resource_rows = result.scalars().all()

    resources: List[Dict[str, Any]] = []
    for resource in resource_rows:
        resources.append({
            "id": resource.id,
            "name": resource.name,
            "description": resource.description,
            "resource_type": resource.resource_type,
            "address": resource.address,
            "ports": resource.ports,
            "protocol": resource.protocol,
            "is_active": resource.is_active,
        })

    return templates.TemplateResponse(
        request=request,
        name="resources_table.html",
        context={"resources": resources},
    )


@ui_router.get("/resources/new", response_class=HTMLResponse)
async def ui_resource_new_form(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="resource_form.html",
        context={
            "resource": None,
            "form_action": "/ui/resources/create",
            "form_title": "Create resource",
            "submit_label": "Create",
        },
    )


@ui_router.get("/resources/{resource_id}/edit", response_class=HTMLResponse)
async def ui_resource_edit_form(resource_id: int, request: Request):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Resource).where(Resource.id == resource_id)
        )
        resource = result.scalar_one_or_none()

    if not resource or not resource.is_active:
        raise HTTPException(status_code=404, detail="Resource not found")

    resource_data = {
        "id": resource.id,
        "name": resource.name,
        "description": resource.description,
        "resource_type": resource.resource_type,
        "address": resource.address,
        "ports": resource.ports,
        "protocol": resource.protocol,
        "is_active": resource.is_active,
    }

    return templates.TemplateResponse(
        request=request,
        name="resource_form.html",
        context={
            "resource": resource_data,
            "form_action": f"/ui/resources/{resource_id}/update",
            "form_title": "Edit resource",
            "submit_label": "Save",
        },
    )


@ui_router.get("/debug/access/form", response_class=HTMLResponse)
async def ui_debug_access_form(request: Request):
    users = await load_active_users()
    return templates.TemplateResponse(
        request=request,
        name="debug_access_form.html",
        context={"users": users},
    )


@ui_router.get("/debug/access/result", response_class=HTMLResponse)
async def ui_debug_access_result(request: Request, user_id: int):
    result = await evaluate_effective_access_for_user(user_id)
    return templates.TemplateResponse(
        request=request,
        name="debug_access_result.html",
        context=result,
    )


@ui_router.get("/debug/peer/form", response_class=HTMLResponse)
async def ui_debug_peer_form(request: Request):
    peers = await load_active_peers()
    return templates.TemplateResponse(
        request=request,
        name="debug_peer_form.html",
        context={"peers": peers},
    )


@ui_router.get("/debug/peer/result", response_class=HTMLResponse)
async def ui_debug_peer_result(request: Request, peer_id: int):
    result = await evaluate_effective_access_for_peer(peer_id=peer_id)
    return templates.TemplateResponse(
        request=request,
        name="debug_peer_result.html",
        context=result,
    )


@ui_router.post("/resources/create", response_class=HTMLResponse)
async def ui_resource_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    resource_type: str = Form(...),
    address: str = Form(...),
    ports: str = Form(""),
    protocol: str = Form("any"),
):
    form_data = {
        "name": name,
        "description": description or None,
        "resource_type": resource_type,
        "address": address,
        "ports": ports or None,
        "protocol": protocol or "any",
    }

    try:
        payload = ResourceCreate(**form_data)
    except ValidationError as e:
        errors = [err["msg"] for err in e.errors()]
        return templates.TemplateResponse(
            request=request,
            name="resource_form.html",
            context={
                "resource": form_data,
                "form_action": "/ui/resources/create",
                "form_title": "Create resource",
                "submit_label": "Create",
                "errors": errors,
            },
            status_code=422,
        )

    async with AsyncSessionLocal() as db:
        await create_resource_service(db, payload)

        result = await db.execute(
            select(Resource)
            .where(Resource.is_active == True)  # noqa: E712
            .order_by(Resource.id.asc())
        )
        resource_rows = result.scalars().all()

    resources: List[Dict[str, Any]] = []
    for resource in resource_rows:
        resources.append({
            "id": resource.id,
            "name": resource.name,
            "description": resource.description,
            "resource_type": resource.resource_type,
            "address": resource.address,
            "ports": resource.ports,
            "protocol": resource.protocol,
            "is_active": resource.is_active,
        })

    return templates.TemplateResponse(
        request=request,
        name="resources_table.html",
        context={"resources": resources},
    )


@ui_router.post("/resources/{resource_id}/update", response_class=HTMLResponse)
async def ui_resource_update(
    resource_id: int,
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    resource_type: str = Form(...),
    address: str = Form(...),
    ports: str = Form(""),
    protocol: str = Form("any"),
):
    form_data = {
        "id": resource_id,
        "name": name,
        "description": description or None,
        "resource_type": resource_type,
        "address": address,
        "ports": ports or None,
        "protocol": protocol or "any",
        "is_active": True,
    }

    try:
        payload = ResourceUpdate(
            name=name,
            description=description or None,
            resource_type=resource_type,
            address=address,
            ports=ports or None,
            protocol=protocol or "any",
        )
    except ValidationError as e:
        errors = [err["msg"] for err in e.errors()]
        return templates.TemplateResponse(
            request=request,
            name="resource_form.html",
            context={
                "resource": form_data,
                "form_action": f"/ui/resources/{resource_id}/update",
                "form_title": "Edit resource",
                "submit_label": "Save",
                "errors": errors,
            },
            status_code=422,
        )

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Resource).where(Resource.id == resource_id)
        )
        resource = result.scalar_one_or_none()

        if not resource or not resource.is_active:
            raise HTTPException(status_code=404, detail="Resource not found")

        await update_resource_service(db, resource, payload)

        result = await db.execute(
            select(Resource)
            .where(Resource.is_active == True)  # noqa: E712
            .order_by(Resource.id.asc())
        )
        resource_rows = result.scalars().all()

    resources: List[Dict[str, Any]] = []
    for resource in resource_rows:
        resources.append({
            "id": resource.id,
            "name": resource.name,
            "description": resource.description,
            "resource_type": resource.resource_type,
            "address": resource.address,
            "ports": resource.ports,
            "protocol": resource.protocol,
            "is_active": resource.is_active,
        })

    return templates.TemplateResponse(
        request=request,
        name="resources_table.html",
        context={"resources": resources},
    )


@ui_router.post("/resources/{resource_id}/delete", response_class=HTMLResponse)
async def ui_resource_delete(resource_id: int, request: Request):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Resource).where(Resource.id == resource_id)
        )
        resource = result.scalar_one_or_none()

        if not resource or not resource.is_active:
            raise HTTPException(status_code=404, detail="Resource not found")

        await soft_delete_resource(db, resource)

        result = await db.execute(
            select(Resource)
            .where(Resource.is_active == True)  # noqa: E712
            .order_by(Resource.id.asc())
        )
        resource_rows = result.scalars().all()

    resources: List[Dict[str, Any]] = []
    for resource in resource_rows:
        resources.append({
            "id": resource.id,
            "name": resource.name,
            "description": resource.description,
            "resource_type": resource.resource_type,
            "address": resource.address,
            "ports": resource.ports,
            "protocol": resource.protocol,
            "is_active": resource.is_active,
        })

    return templates.TemplateResponse(
        request=request,
        name="resources_table.html",
        context={"resources": resources},
    )


@ui_router.post("/peers/{peer_id}/recalculate", response_class=HTMLResponse)
async def ui_peers_recalculate(peer_id: int, request: Request):
    async with AsyncSessionLocal() as db:
        await recalculate_peer_by_id(db, peer_id)

        result = await db.execute(select(Peer).order_by(Peer.id.asc()))
        peer_rows = result.scalars().all()

    peers: List[Dict[str, Any]] = []
    for peer in peer_rows:
        peers.append({
            "id": peer.id,
            "user_id": peer.user_id,
            "vpn_ip": peer.vpn_ip,
            "allowed_ips": peer.allowed_ips,
            "provisioning_status": peer.provisioning_status,
            "public_key": peer.public_key,
        })

    return templates.TemplateResponse(
        request=request,
        name="peers_table.html",
        context={"peers": peers},
    )


@ui_router.post("/peers/{peer_id}/provision", response_class=HTMLResponse)
async def ui_peers_provision(peer_id: int, request: Request):
    async with AsyncSessionLocal() as db:
        await provision_peer_by_id(db, peer_id)

        result = await db.execute(select(Peer).order_by(Peer.id.asc()))
        peer_rows = result.scalars().all()

    peers: List[Dict[str, Any]] = []
    for peer in peer_rows:
        peers.append({
            "id": peer.id,
            "user_id": peer.user_id,
            "vpn_ip": peer.vpn_ip,
            "allowed_ips": peer.allowed_ips,
            "provisioning_status": peer.provisioning_status,
            "public_key": peer.public_key,
        })

    return templates.TemplateResponse(
        request=request,
        name="peers_table.html",
        context={"peers": peers},
    )


@ui_router.get("/tenants/table", response_class=HTMLResponse)
async def ui_tenants_table(request: Request):
    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000",
        timeout=10.0,
    ) as client:
        resp = await client.get("/api/v1/tenants/")
        resp.raise_for_status()
        tenants: List[Dict[str, Any]] = resp.json()

    return templates.TemplateResponse(
        request=request,
        name="tenants_table.html",
        context={"tenants": tenants},
    )


@ui_router.get("/tenants/new", response_class=HTMLResponse)
async def ui_tenant_new_form(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="tenant_form.html",
        context={
            "tenant": None,
            "form_action": "/ui/tenants/create",
            "form_title": "Create tenant",
            "submit_label": "Create",
        },
    )


@ui_router.get("/tenants/{tenant_id}/edit", response_class=HTMLResponse)
async def ui_tenant_edit_form(tenant_id: UUID, request: Request):
    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000",
        timeout=10.0,
    ) as client:
        resp = await client.get(f"/api/v1/tenants/{tenant_id}")
        resp.raise_for_status()
        tenant = resp.json()

    return templates.TemplateResponse(
        request=request,
        name="tenant_form.html",
        context={
            "tenant": tenant,
            "form_action": f"/ui/tenants/{tenant_id}/update",
            "form_title": "Edit tenant",
            "submit_label": "Save",
        },
    )


@ui_router.post("/tenants/create", response_class=HTMLResponse)
async def ui_tenant_create(
    request: Request,
    name: str = Form(...),
    slug: str = Form(...),
):
    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000",
        timeout=10.0,
    ) as client:
        resp = await client.post(
            "/api/v1/tenants/",
            json={"name": name, "slug": slug},
        )
        resp.raise_for_status()

        tenants_resp = await client.get("/api/v1/tenants/")
        tenants_resp.raise_for_status()
        tenants: List[Dict[str, Any]] = tenants_resp.json()

    return templates.TemplateResponse(
        request=request,
        name="tenants_table.html",
        context={"tenants": tenants},
    )


@ui_router.post("/tenants/{tenant_id}/update", response_class=HTMLResponse)
async def ui_tenant_update(
    tenant_id: UUID,
    request: Request,
    name: str = Form(...),
    slug: str = Form(...),
):
    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000",
        timeout=10.0,
    ) as client:
        resp = await client.put(
            f"/api/v1/tenants/{tenant_id}",
            json={"name": name, "slug": slug},
        )
        resp.raise_for_status()

        tenants_resp = await client.get("/api/v1/tenants/")
        tenants_resp.raise_for_status()
        tenants: List[Dict[str, Any]] = tenants_resp.json()

    return templates.TemplateResponse(
        request=request,
        name="tenants_table.html",
        context={"tenants": tenants},
    )


@ui_router.post("/tenants/{tenant_id}/delete", response_class=HTMLResponse)
async def ui_tenant_delete(tenant_id: UUID, request: Request):
    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000",
        timeout=10.0,
    ) as client:
        resp = await client.delete(f"/api/v1/tenants/{tenant_id}")
        resp.raise_for_status()

        tenants_resp = await client.get("/api/v1/tenants/")
        tenants_resp.raise_for_status()
        tenants: List[Dict[str, Any]] = tenants_resp.json()

    return templates.TemplateResponse(
        request=request,
        name="tenants_table.html",
        context={"tenants": tenants},
    )


@ui_router.post("/tenants/{tenant_id}/toggle", response_class=HTMLResponse)
async def ui_tenant_toggle(tenant_id: UUID, request: Request):
    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000",
        timeout=10.0,
    ) as client:
        resp = await client.post(f"/api/v1/tenants/{tenant_id}/toggle")
        resp.raise_for_status()

        tenants_resp = await client.get("/api/v1/tenants/")
        tenants_resp.raise_for_status()
        tenants: List[Dict[str, Any]] = tenants_resp.json()

    return templates.TemplateResponse(
        request=request,
        name="tenants_table.html",
        context={"tenants": tenants},
    )


@ui_router.get("/policies/table", response_class=HTMLResponse)
async def ui_policies_table(request: Request):
    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000",
        timeout=10.0,
    ) as client:
        policies_resp = await client.get("/api/v1/policies/")
        policies_resp.raise_for_status()
        policies = policies_resp.json()

        resources_resp = await client.get("/api/v1/resources/")
        resources_resp.raise_for_status()
        resources = resources_resp.json()

    async with AsyncSessionLocal() as db:
        users_result = await db.execute(select(User).order_by(User.username.asc()))
        groups_result = await db.execute(select(Group).order_by(Group.name.asc()))

        users = {u.id: u for u in users_result.scalars().all()}
        groups = {g.id: g for g in groups_result.scalars().all()}

    resource_map = {r["id"]: r for r in resources}

    for policy in policies:
        if policy.get("user_id"):
            user = users.get(policy["user_id"])
            policy["subject_label"] = f"user: {user.username}" if user else f"user #{policy['user_id']}"
        elif policy.get("group_id"):
            group = groups.get(policy["group_id"])
            policy["subject_label"] = f"group: {group.name}" if group else f"group #{policy['group_id']}"
        else:
            policy["subject_label"] = "unknown"

        resource = resource_map.get(policy["resource_id"])
        policy["resource_label"] = resource["name"] if resource else f"resource #{policy['resource_id']}"

    return templates.TemplateResponse(
        request=request,
        name="policies_table.html",
        context={"policies": policies},
    )


@ui_router.get("/policies/new", response_class=HTMLResponse)
async def ui_policy_new_form(request: Request):
    options = await load_policy_form_options()
    return templates.TemplateResponse(
        request=request,
        name="policy_form.html",
        context={
            "policy": None,
            "form_action": "/ui/policies/create",
            "form_title": "Create policy",
            "submit_label": "Create",
            **options,
        },
    )


@ui_router.get("/policies/{policy_id}/edit", response_class=HTMLResponse)
async def ui_policy_edit_form(policy_id: int, request: Request):
    options = await load_policy_form_options()

    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000",
        timeout=10.0,
    ) as client:
        resp = await client.get(f"/api/v1/policies/{policy_id}")
        resp.raise_for_status()
        policy = resp.json()

    return templates.TemplateResponse(
        request=request,
        name="policy_form.html",
        context={
            "policy": policy,
            "form_action": f"/ui/policies/{policy_id}/update",
            "form_title": "Edit policy",
            "submit_label": "Save",
            **options,
        },
    )


@ui_router.get("/debug/check/form", response_class=HTMLResponse)
async def ui_debug_check_form(
    request: Request,
    user_id: int | None = None,
    resource_id: int | None = None,
):
    options = await load_debug_check_options()
    return templates.TemplateResponse(
        request=request,
        name="debug_check_form.html",
        context={
            **options,
            "prefill_user_id": user_id,
            "prefill_resource_id": resource_id,
        },
    )


@ui_router.get("/debug/check/result", response_class=HTMLResponse)
async def ui_debug_check_result(request: Request, user_id: int, resource_id: int):
    result = await evaluate_user_resource_access(user_id=user_id, resource_id=resource_id)
    return templates.TemplateResponse(
        request=request,
        name="debug_check_result.html",
        context=result,
    )


@ui_router.post("/policies/create", response_class=HTMLResponse)
async def ui_policy_create(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    subject_type: str = Form(...),
    user_id: str = Form(""),
    group_id: str = Form(""),
    resource_id: int = Form(...),
    effect: str = Form(...),
    priority: int = Form(100),
    conditions: str = Form(""),
):
    payload = {
        "name": name,
        "description": description or None,
        "user_id": int(user_id) if subject_type == "user" and user_id else None,
        "group_id": int(group_id) if subject_type == "group" and group_id else None,
        "resource_id": resource_id,
        "effect": effect,
        "priority": priority,
        "conditions": conditions or None,
    }

    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000",
        timeout=10.0,
    ) as client:
        resp = await client.post("/api/v1/policies/", json=payload)
        resp.raise_for_status()


    return await ui_policies_table(request)


@ui_router.post("/policies/{policy_id}/update", response_class=HTMLResponse)
async def ui_policy_update(
    policy_id: int,
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    subject_type: str = Form(...),
    user_id: str = Form(""),
    group_id: str = Form(""),
    resource_id: int = Form(...),
    effect: str = Form(...),
    priority: int = Form(100),
    conditions: str = Form(""),
):
    payload = {
        "name": name,
        "description": description or None,
        "user_id": int(user_id) if subject_type == "user" and user_id else None,
        "group_id": int(group_id) if subject_type == "group" and group_id else None,
        "resource_id": resource_id,
        "effect": effect,
        "priority": priority,
        "conditions": conditions or None,
    }

    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000",
        timeout=10.0,
    ) as client:
        resp = await client.put(f"/api/v1/policies/{policy_id}", json=payload)
        resp.raise_for_status()

    return await ui_policies_table(request)


@ui_router.post("/policies/{policy_id}/delete", response_class=HTMLResponse)
async def ui_policy_delete(policy_id: int, request: Request):
    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000",
        timeout=10.0,
    ) as client:
        resp = await client.delete(f"/api/v1/policies/{policy_id}")
        resp.raise_for_status()

    return await ui_policies_table(request)


async def load_policy_form_options() -> dict:
    async with AsyncSessionLocal() as db:
        users_result = await db.execute(
            select(User).where(User.is_active == True).order_by(User.username.asc())  # noqa: E712
        )
        groups_result = await db.execute(select(Group).order_by(Group.name.asc()))

        users = [
            {
                "id": user.id,
                "label": f"{user.username} ({user.email})",
            }
            for user in users_result.scalars().all()
        ]

        groups = [
            {
                "id": group.id,
                "label": group.name,
            }
            for group in groups_result.scalars().all()
        ]

    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:8000",
        timeout=10.0,
    ) as client:
        resources_resp = await client.get("/api/v1/resources/")
        resources_resp.raise_for_status()
        resources = resources_resp.json()

    return {
        "users": users,
        "groups": groups,
        "resources": resources,
    }


async def load_active_users() -> list[dict]:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(User)
            .where(User.is_active == True)  # noqa: E712
            .order_by(User.username.asc())
        )
        users = result.scalars().all()

    return [
        {
            "id": user.id,
            "label": f"{user.username} ({user.email})",
        }
        for user in users
    ]


async def load_active_peers() -> list[dict]:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Peer).order_by(Peer.id.asc())
        )
        peers = result.scalars().all()

        user_ids = {p.user_id for p in peers if p.user_id is not None}
        users_map: dict[int, User] = {}

        if user_ids:
            users_result = await db.execute(
                select(User).where(User.id.in_(user_ids))
            )
            for user in users_result.scalars().all():
                users_map[user.id] = user

    items: list[dict] = []
    for peer in peers:
        user_label = f"user #{peer.user_id}"
        if peer.user_id in users_map:
            u = users_map[peer.user_id]
            user_label = f"{u.username} ({u.email})"

        items.append(
            {
                "id": peer.id,
                "public_key": peer.public_key,
                "vpn_ip": peer.vpn_ip,
                "allowed_ips": peer.allowed_ips,
                "provisioning_status": peer.provisioning_status.value if hasattr(peer.provisioning_status, "value") else str(peer.provisioning_status),
                "user_id": peer.user_id,
                "user_label": user_label,
            }
        )

    return items


async def load_debug_check_options() -> dict:
    async with AsyncSessionLocal() as db:
        users_result = await db.execute(
            select(User)
            .where(User.is_active == True)  # noqa: E712
            .order_by(User.username.asc())
        )
        resources_result = await db.execute(
            select(Resource)
            .where(Resource.is_active == True)  # noqa: E712
            .order_by(Resource.name.asc())
        )

        users = users_result.scalars().all()
        resources = resources_result.scalars().all()

    return {
        "users": [
            {
                "id": user.id,
                "label": f"{user.username} ({user.email})",
            }
            for user in users
        ],
        "resources": [
            {
                "id": resource.id,
                "label": f"{resource.name} ({resource.resource_type.value if hasattr(resource.resource_type, 'value') else str(resource.resource_type)})",
            }
            for resource in resources
        ],
    }


async def evaluate_effective_access_for_user(user_id: int) -> dict:
    async with AsyncSessionLocal() as db:
        user_result = await db.execute(
            select(User).where(User.id == user_id, User.is_active == True)  # noqa: E712
        )
        user = user_result.scalar_one_or_none()
        if not user:
            return {"user": None, "rows": []}

        group_ids_result = await db.execute(
            select(user_group.c.group_id).where(user_group.c.user_id == user_id)
        )
        group_ids = list(group_ids_result.scalars().all())

        resources_result = await db.execute(
            select(Resource)
            .where(Resource.is_active == True)  # noqa: E712
            .order_by(Resource.id.asc())
        )
        resources = list(resources_result.scalars().all())

        policies_result = await db.execute(
            select(Policy)
            .where(Policy.is_active == True)  # noqa: E712
            .order_by(Policy.priority.asc(), Policy.id.asc())
        )
        all_policies = list(policies_result.scalars().all())

        rows = []

        for resource in resources:
            matched = []

            for policy in all_policies:
                if policy.resource_id != resource.id:
                    continue

                applies = False
                subject_label = "global"

                if policy.user_id is not None and policy.user_id == user.id:
                    applies = True
                    subject_label = f"user:{user.username}"
                elif policy.group_id is not None and policy.group_id in group_ids:
                    applies = True
                    subject_label = f"group:{policy.group_id}"
                elif policy.user_id is None and policy.group_id is None:
                    applies = True
                    subject_label = "global"

                if applies:
                    matched.append(
                        {
                            "id": policy.id,
                            "name": policy.name,
                            "effect": policy.effect.value if hasattr(policy.effect, "value") else str(policy.effect),
                            "priority": policy.priority,
                            "subject": subject_label,
                            "conditions": policy.conditions,
                        }
                    )

            decision = "deny"
            reason = "implicit deny"
            winning_policy = None

            if matched:
                matched = sorted(matched, key=lambda x: (x["priority"], x["id"]))
                deny_matches = [p for p in matched if p["effect"] == "deny"]
                allow_matches = [p for p in matched if p["effect"] == "allow"]

                if deny_matches:
                    winning_policy = deny_matches[0]
                    decision = "deny"
                    reason = f"explicit deny by policy #{winning_policy['id']} ({winning_policy['name']})"
                elif allow_matches:
                    winning_policy = allow_matches[0]
                    decision = "allow"
                    reason = f"explicit allow by policy #{winning_policy['id']} ({winning_policy['name']})"

            rows.append(
                {
                    "resource_id": resource.id,
                    "resource_name": resource.name,
                    "resource_type": resource.resource_type.value if hasattr(resource.resource_type, "value") else str(resource.resource_type),
                    "address": resource.address,
                    "protocol": resource.protocol,
                    "decision": decision,
                    "reason": reason,
                    "matched_policies": matched,
                    "winning_policy": winning_policy,
                }
            )

    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "group_ids": group_ids,
        },
        "rows": rows,
    }


async def evaluate_effective_access_for_peer(peer_id: int) -> dict:
    async with AsyncSessionLocal() as db:
        peer_result = await db.execute(
            select(Peer).where(Peer.id == peer_id)
        )
        peer = peer_result.scalar_one_or_none()

        if not peer:
            return {
                "peer": None,
                "user": None,
                "rows": [],
            }

    user_result = await evaluate_effective_access_for_user(user_id=peer.user_id)

    return {
        "peer": {
            "id": peer.id,
            "public_key": peer.public_key,
            "vpn_ip": peer.vpn_ip,
            "allowed_ips": peer.allowed_ips,
            "provisioning_status": peer.provisioning_status.value if hasattr(peer.provisioning_status, "value") else str(peer.provisioning_status),
            "user_id": peer.user_id,
        },
        "user": user_result["user"],
        "rows": user_result["rows"],
    }


async def evaluate_user_resource_access(user_id: int, resource_id: int) -> dict:
    async with AsyncSessionLocal() as db:
        user_result = await db.execute(
            select(User).where(User.id == user_id, User.is_active == True)  # noqa: E712
        )
        resource_result = await db.execute(
            select(Resource).where(Resource.id == resource_id, Resource.is_active == True)  # noqa: E712
        )

        user = user_result.scalar_one_or_none()
        resource = resource_result.scalar_one_or_none()

        if not user or not resource:
            return {
                "user": None,
                "resource": None,
                "decision": "deny",
                "reason": "user or resource not found",
                "matched_policies": [],
                "winning_policy": None,
                "group_names": [],
            }

        group_ids_result = await db.execute(
            select(user_group.c.group_id).where(user_group.c.user_id == user.id)
        )
        group_ids = list(group_ids_result.scalars().all())

        group_names = []
        if group_ids:
            groups_result = await db.execute(
                select(Group).where(Group.id.in_(group_ids)).order_by(Group.name.asc())
            )
            groups = groups_result.scalars().all()
            group_names = [g.name for g in groups]

        policies_result = await db.execute(
            select(Policy)
            .where(
                Policy.is_active == True,  # noqa: E712
                Policy.resource_id == resource.id,
            )
            .order_by(Policy.priority.asc(), Policy.id.asc())
        )
        policies = list(policies_result.scalars().all())

        matched_policies = []

        for policy in policies:
            applies = False
            subject_label = "global"

            if policy.user_id is not None and policy.user_id == user.id:
                applies = True
                subject_label = f"user:{user.username}"
            elif policy.group_id is not None and policy.group_id in group_ids:
                applies = True
                group_name = next((name for name in group_names if name), None)
                subject_label = f"group:{group_name or policy.group_id}"
            elif policy.user_id is None and policy.group_id is None:
                applies = True
                subject_label = "global"

            if applies:
                matched_policies.append(
                    {
                        "id": policy.id,
                        "name": policy.name,
                        "effect": policy.effect.value if hasattr(policy.effect, "value") else str(policy.effect),
                        "priority": policy.priority,
                        "subject": subject_label,
                        "conditions": policy.conditions,
                    }
                )

        decision = "deny"
        reason = "implicit deny"
        winning_policy = None

        if matched_policies:
            matched_policies = sorted(matched_policies, key=lambda x: (x["priority"], x["id"]))
            deny_matches = [p for p in matched_policies if p["effect"] == "deny"]
            allow_matches = [p for p in matched_policies if p["effect"] == "allow"]

            if deny_matches:
                winning_policy = deny_matches[0]
                decision = "deny"
                reason = f"explicit deny by policy #{winning_policy['id']} ({winning_policy['name']})"
            elif allow_matches:
                winning_policy = allow_matches[0]
                decision = "allow"
                reason = f"explicit allow by policy #{winning_policy['id']} ({winning_policy['name']})"

        return {
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            },
            "resource": {
                "id": resource.id,
                "name": resource.name,
                "resource_type": resource.resource_type.value if hasattr(resource.resource_type, "value") else str(resource.resource_type),
                "address": resource.address,
                "protocol": resource.protocol,
                "ports": resource.ports,
            },
            "decision": decision,
            "reason": reason,
            "matched_policies": matched_policies,
            "winning_policy": winning_policy,
            "group_names": group_names,
        }


app.include_router(ui_router)

