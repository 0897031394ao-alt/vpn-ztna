import io
from datetime import timedelta, timezone
import json
from typing import Optional
from urllib.parse import urlencode
from uuid import UUID

import qrcode
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_admin
from app.api.ui_admin import require_ui_admin
from app.core.security import hash_password
from app.db.session import AsyncSessionLocal, get_db
from app.models.auth_session import AuthSession
from app.models.group import Group, user_group
from app.models.peer import Peer, ProvisioningStatus
from app.models.policy import Policy
from app.models.resource import Resource
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.resource import ResourceCreate, ResourceUpdate
from app.schemas.tenant import TenantCreate, TenantUpdate
from app.schemas.group import GroupCreate, GroupUpdate
from app.services.config_service import build_client_config_for_peer
from app.services.peer_service import (
    provision_peer_by_id,
    recalculate_peer_by_id,
    recalculate_peers_for_user,
    register_peer_for_user,
    remove_peer_by_id,
)
from app.services.policy_service import create_policy, delete_policy, update_policy
from app.services.resource_service import (
    create_resource as create_resource_service,
    recalculate_peers_for_resource,
    soft_delete_resource,
    update_resource as update_resource_service,
)
from app.services.tenant_service import (
    create_tenant,
    delete_tenant,
    get_tenant,
    list_tenants,
    toggle_tenant,
    update_tenant,
)
from app.services.peer_service import (
    provision_peer_by_id,
    recalculate_peer_by_id,
    regenerate_peer_keys,
)
from app.services.group_service import (
    create_group, update_group, soft_delete_group, get_group_with_users,
)

templates = Jinja2Templates(directory="/app/app_ui/templates")

# All /ui/* routes are protected by the central UI auth middleware.
ui_fragments_router = APIRouter(
    dependencies=[Depends(require_ui_admin)],
)


async def get_active_resource_or_404(db: AsyncSession, resource_id: int) -> Resource:
    result = await db.execute(
        select(Resource).where(
            Resource.id == resource_id,
            Resource.is_active.is_(True),
        )
    )
    resource = result.scalar_one_or_none()
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    return resource


def parse_optional_int(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    value = str(value).strip()
    if not value:
        return None
    return int(value)



async def get_affected_user_ids_for_ui_policy(
    db: AsyncSession,
    policy: Policy,
) -> set[int]:
    """Return users affected by a User- or Group-scoped policy."""
    user_ids: set[int] = set()

    if policy.user_id is not None:
        user_ids.add(policy.user_id)

    if policy.group_id is not None:
        result = await db.execute(
            select(user_group.c.user_id).where(
                user_group.c.group_id == policy.group_id
            )
        )
        user_ids.update(result.scalars().all())

    return user_ids


async def recalculate_users_after_policy_change(
    db: AsyncSession,
    user_ids: set[int],
) -> None:
    """Recalculate existing peers or create one for newly entitled users."""
    for user_id in sorted(user_ids):
        peers = await recalculate_peers_for_user(db, user_id)

        # A user with effective allow-routes but no active peer needs an
        # initial WireGuard identity.
        if not peers:
            try:
                await register_peer_for_user(db, user_id)
            except HTTPException as exc:
                # register_peer_for_user intentionally rejects a policy set
                # that yields no effective allow-routes (for example deny-only).
                if exc.status_code != status.HTTP_403_FORBIDDEN:
                    raise

def build_policy_form_state(
    *,
    name: str,
    description: str,
    subject_type: str,
    user_id,
    group_id,
    resource_id,
    effect: str,
    priority: int,
    conditions: str,
    policy_id: int | None = None,
) -> dict:
    parsed_user_id = parse_optional_int(user_id) if subject_type == "user" else None
    parsed_group_id = parse_optional_int(group_id) if subject_type == "group" else None
    parsed_resource_id = parse_optional_int(resource_id)

    policy = {
        "name": name,
        "description": description,
        "subject_type": subject_type,
        "user_id": parsed_user_id,
        "group_id": parsed_group_id,
        "resource_id": parsed_resource_id,
        "effect": effect,
        "priority": priority,
        "conditions": conditions,
    }
    if policy_id is not None:
        policy["id"] = policy_id
    return policy


def policy_form_response(
    request: Request,
    *,
    form_title: str,
    form_action: str,
    submit_label: str,
    policy: dict,
    resources: list,
    users: list,
    groups: list,
    error_message: str,
    page: int = 1,
    limit: int = 20,
    status_filter: str = "active",
):
    response = templates.TemplateResponse(
        request=request,
        name="policy_form.html",
        context={
            "form_title": form_title,
            "form_action": form_action,
            "submit_label": submit_label,
            "policy": policy,
            "resources": resources,
            "users": users,
            "groups": groups,
            "error_message": error_message,
            "page": page,
            "limit": limit,
            "status": status_filter,
        },
        status_code=status.HTTP_200_OK,
    )
    return response


async def load_policy_form_options(
    db: AsyncSession = Depends(get_db),
) -> tuple[list[dict], list[dict], list[dict]]:
    resources_result = await db.execute(
        select(Resource)
        .where(Resource.is_active == True)  # noqa: E712
        .order_by(Resource.name.asc(), Resource.id.asc())
    )
    users_result = await db.execute(
        select(User).order_by(User.username.asc(), User.id.asc())
    )
    groups_result = await db.execute(
        select(Group).order_by(Group.name.asc(), Group.id.asc())
    )

    resources = [
        {
            "id": r.id,
            "name": r.name,
            "resource_type": r.resource_type,
            "label": f"{r.name} ({r.resource_type})",
        }
        for r in resources_result.scalars().all()
    ]

    users = [
        {
            "id": u.id,
            "label": u.username or u.email or f"user-{u.id}",
        }
        for u in users_result.scalars().all()
    ]

    groups = [
        {
            "id": g.id,
            "label": g.name or f"group-{g.id}",
        }
        for g in groups_result.scalars().all()
    ]

    return resources, users, groups


@ui_fragments_router.get("/ui/resources/table", response_class=HTMLResponse)
async def ui_resources_table(
    request: Request,
    page: int = 1,
    limit: int = 20,
    status: str = "active",
    db: AsyncSession = Depends(get_db),
):
    return await render_resources_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status,
    )


def build_resource_form_state(resource: Resource | None = None) -> dict:
    if resource is None:
        return {
            "name": "",
            "description": "",
            "resource_type": "cidr",
            "address": "",
            "ports": "",
            "protocol": "any",
            "is_active": True,
        }

    return {
        "id": resource.id,
        "name": resource.name or "",
        "description": getattr(resource, "description", "") or "",
        "resource_type": (
            resource.resource_type.value
            if getattr(resource, "resource_type", None) and hasattr(resource.resource_type, "value")
            else str(getattr(resource, "resource_type", "") or "")
        ),
        "address": getattr(resource, "address", "") or "",
        "ports": getattr(resource, "ports", "") or "",
        "protocol": getattr(resource, "protocol", "any") or "any",
        "is_active": bool(getattr(resource, "is_active", True)),
    }


def resource_form_response(
    request: Request,
    *,
    form_title: str,
    form_action: str,
    submit_label: str,
    resource: dict,
    error_message: str = "",
    page: int = 1,
    limit: int = 20,
    status_filter: str = "active",
    status_code: int = status.HTTP_200_OK,
):
    response = templates.TemplateResponse(
        request=request,
        name="resource_form.html",
        context={
            "form_title": form_title,
            "form_action": form_action,
            "submit_label": submit_label,
            "resource": resource,
            "error_message": error_message,
            "page": page,
            "limit": limit,
            "status": status_filter,
        },
        status_code=status_code,
    )
    response.headers["HX-Retarget"] = "#modal-root"
    return response


async def render_resources_table_paginated(
    request: Request,
    db: AsyncSession,
    page: int = 1,
    limit: int = 20,
    status_filter: str = "active",
) -> HTMLResponse:
    page = max(page, 1)
    if limit not in {5, 10, 20, 50, 100}:
        limit = 20

    status_filter = (status_filter or "active").strip().lower()
    if status_filter not in {"active", "inactive", "all"}:
        status_filter = "active"

    query = select(Resource)
    count_query = select(func.count()).select_from(Resource)

    if status_filter == "active":
        query = query.where(Resource.is_active.is_(True))
        count_query = count_query.where(Resource.is_active.is_(True))
    elif status_filter == "inactive":
        query = query.where(Resource.is_active.is_(False))
        count_query = count_query.where(Resource.is_active.is_(False))

    total = (await db.execute(count_query)).scalar() or 0
    total_pages = max((total + limit - 1) // limit, 1)

    if page > total_pages:
        page = total_pages

    query = query.order_by(Resource.id.asc()).offset((page - 1) * limit).limit(limit)
    result = await db.execute(query)
    resources = result.scalars().all()

    resource_rows = [
        {
            "id": r.id,
            "name": r.name,
            "resource_type": (
                r.resource_type.value
                if getattr(r, "resource_type", None) and hasattr(r.resource_type, "value")
                else str(getattr(r, "resource_type", "") or "")
            ),
            "address": getattr(r, "address", "") or "—",
            "ports": getattr(r, "ports", "") or None,
            "protocol": getattr(r, "protocol", "any") or "any",
            "is_active": bool(getattr(r, "is_active", True)),
        }
        for r in resources
    ]

    html = templates.get_template("resources_table_paginated.html").render(
        resources=resource_rows,
        request=request,
        page=page,
        limit=limit,
        status=status_filter,
        total=total,
        total_pages=total_pages,
    )
    return HTMLResponse(html)


@ui_fragments_router.get("/ui/resources/new", response_class=HTMLResponse)
async def ui_resource_new_form(request: Request):
    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")

    return resource_form_response(
        request,
        form_title="New resource",
        form_action="/ui/resources/create",
        submit_label="Create resource",
        resource=build_resource_form_state(),
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


@ui_fragments_router.post("/ui/resources/create", response_class=HTMLResponse)
async def ui_resource_create_submit(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    form = await request.form()
    page = int(str(form.get("page", 1) or 1))
    limit = int(str(form.get("limit", 20) or 20))
    status_filter = str(form.get("status", "active") or "active")
    payload = {
        "name": str(form.get("name", "")).strip(),
        "description": str(form.get("description", "")).strip() or None,
        "resource_type": str(form.get("resource_type", "cidr")).strip() or "cidr",
        "address": str(form.get("address", "")).strip(),
        "ports": str(form.get("ports", "")).strip() or None,
        "protocol": str(form.get("protocol", "any")).strip() or "any",
    }

    try:
        resource_in = ResourceCreate(**payload)
        await create_resource_service(db, resource_in)
        await db.commit()
    except ValidationError as exc:
        return resource_form_response(
            request,
            form_title="New resource",
            form_action="/ui/resources/create",
            submit_label="Create resource",
            resource=payload,
            error_message=str(exc),
            page=page,
            limit=limit,
            status_filter=status_filter,
            status_code=200,
        )
    except Exception as exc:
        await db.rollback()
        return resource_form_response(
            request,
            form_title="New resource",
            form_action="/ui/resources/create",
            submit_label="Create resource",
            resource=payload,
            error_message=str(exc),
            page=page,
            limit=limit,
            status_filter=status_filter,
            status_code=400,
        )

    return await render_resources_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


@ui_fragments_router.get("/ui/resources/{resource_id}/edit", response_class=HTMLResponse)
async def ui_resource_edit_form(
    request: Request,
    resource_id: int,
    db: AsyncSession = Depends(get_db),
):
    resource = await db.get(Resource, resource_id)
    if not resource:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Resource not found.</div>",
            status_code=404,
        )

    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")

    return resource_form_response(
        request,
        form_title="Edit resource",
        form_action=f"/ui/resources/{resource_id}/edit",
        submit_label="Save changes",
        resource=build_resource_form_state(resource),
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


@ui_fragments_router.post("/ui/resources/{resource_id}/edit", response_class=HTMLResponse)
async def ui_resource_edit_submit(
    request: Request,
    resource_id: int,
    db: AsyncSession = Depends(get_db),
):
    resource = await db.get(Resource, resource_id)
    if not resource:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Resource not found.</div>",
            status_code=404,
        )

    form = await request.form()
    page = int(str(form.get("page", 1) or 1))
    limit = int(str(form.get("limit", 20) or 20))
    status_filter = str(form.get("status", "active") or "active")
    payload = {
        "name": str(form.get("name", "")).strip(),
        "description": str(form.get("description", "")).strip() or None,
        "resource_type": str(form.get("resource_type", "cidr")).strip() or "cidr",
        "address": str(form.get("address", "")).strip(),
        "ports": str(form.get("ports", "")).strip() or None,
        "protocol": str(form.get("protocol", "any")).strip() or "any",
    }

    try:
        resource_in = ResourceUpdate(**payload)
        await update_resource_service(db, resource_id, resource_in)
        await db.commit()
    except ValidationError as exc:
        payload["id"] = resource_id
        return resource_form_response(
            request,
            form_title="Edit resource",
            form_action=f"/ui/resources/{resource_id}/edit",
            submit_label="Save changes",
            resource=payload,
            error_message=str(exc),
            page=page,
            limit=limit,
            status_filter=status_filter,
            status_code=200,
        )
    except Exception as exc:
        await db.rollback()
        payload["id"] = resource_id
        return resource_form_response(
            request,
            form_title="Edit resource",
            form_action=f"/ui/resources/{resource_id}/edit",
            submit_label="Save changes",
            resource=payload,
            error_message=str(exc),
            page=page,
            limit=limit,
            status_filter=status_filter,
            status_code=400,
        )

    return await render_resources_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


@ui_fragments_router.post("/ui/resources/{resource_id}/delete", response_class=HTMLResponse)
async def ui_resource_delete(
    request: Request,
    resource_id: int,
    db: AsyncSession = Depends(get_db),
):
    resource = await db.get(Resource, resource_id)
    if not resource:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Resource not found.</div>",
            status_code=404,
        )

    try:
        await soft_delete_resource(db, resource_id)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        return HTMLResponse(
            f"<div class='px-4 py-3 text-sm text-rose-300'>{str(exc)}</div>",
            status_code=400,
        )

    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")

    return await render_resources_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


@ui_fragments_router.get("/ui/users/table", response_class=HTMLResponse)
async def ui_users_table(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).order_by(User.id.asc()))
    users = result.scalars().all()

    user_rows = [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "is_active": u.is_active,
            "is_admin": u.is_admin,
            "created_at": u.created_at.strftime("%Y-%m-%d %H:%M") if u.created_at else "—",
        }
        for u in users
    ]

    return templates.TemplateResponse(
        request=request,
        name="users_table.html",
        context={"users": user_rows},
    )


@ui_fragments_router.get("/ui/users/table-paginated", response_class=HTMLResponse)
async def ui_users_table_paginated(
    request: Request,
    page: int = 1,
    limit: int = 20,
    status: str = "active",
    db: AsyncSession = Depends(get_db),
):
    page = max(page, 1)

    allowed_limits = {5, 10, 20, 50, 100}
    if limit not in allowed_limits:
        limit = 20

    base_query = select(User)

    if status == "active":
        base_query = base_query.where(User.is_active.is_(True))
    elif status == "inactive":
        base_query = base_query.where(User.is_active.is_(False))
    else:
        status = "all"

    total_result = await db.execute(
        select(func.count()).select_from(base_query.subquery())
    )
    total = total_result.scalar_one() or 0

    total_pages = max((total + limit - 1) // limit, 1)
    if page > total_pages:
        page = total_pages

    result = await db.execute(
        base_query.order_by(User.id.asc()).offset((page - 1) * limit).limit(limit)
    )
    users = result.scalars().all()

    user_rows = [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "is_active": u.is_active,
            "is_admin": u.is_admin,
            "created_at": u.created_at.strftime("%Y-%m-%d %H:%M") if u.created_at else "—",
        }
        for u in users
    ]

    return templates.TemplateResponse(
        request=request,
        name="users_table_paginated.html",
        context={
            "users": user_rows,
            "filters": {
                "page": page,
                "limit": limit,
                "status": status,
                "total": total,
                "total_pages": total_pages,
            },
        },
    )


@ui_fragments_router.get("/ui/users/{user_id}/edit", response_class=HTMLResponse)
async def ui_user_edit_form(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(User)
        .options(selectinload(User.groups))
        .where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    if not user:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>User not found.</div>",
            status_code=404,
        )

    groups_result = await db.execute(
        select(Group).order_by(Group.name.asc(), Group.id.asc())
    )
    groups = groups_result.scalars().all()
    selected_group_ids = [g.id for g in user.groups]

    return templates.TemplateResponse(
        request=request,
        name="user_form.html",
        context={
            "user": user,
            "form_action": f"/ui/users/{user_id}/edit",
            "submit_label": "Save changes",
            "groups": groups,
            "selected_group_ids": selected_group_ids,
            "page": int(request.query_params.get("page", 1) or 1),
            "limit": int(request.query_params.get("limit", 20) or 20),
            "status": request.query_params.get("status", "active"),
        },
    )


@ui_fragments_router.post("/ui/users/{user_id}/edit", response_class=HTMLResponse)
async def ui_user_edit_submit(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(get_db),
):
    form = await request.form()

    page = int(form.get("page", 1) or 1)
    limit = int(form.get("limit", 20) or 20)
    status_filter = str(form.get("status", "active") or "active")

    result = await db.execute(
        select(User)
        .options(selectinload(User.groups))
        .where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    if not user:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>User not found.</div>",
            status_code=404,
        )

    user.username = str(form.get("username", "")).strip()
    user.email = str(form.get("email", "")).strip()
    user.is_active = form.get("is_active") == "on"
    user.is_admin = form.get("is_admin") == "on"

    raw_group_ids = form.getlist("group_ids")
    group_ids = []
    for value in raw_group_ids:
        value = str(value).strip()
        if value.isdigit():
            group_ids.append(int(value))

    if group_ids:
        groups_result = await db.execute(
            select(Group)
            .where(Group.id.in_(group_ids))
            .order_by(Group.name.asc(), Group.id.asc())
        )
        groups = groups_result.scalars().all()
    else:
        groups = []

    user.groups = groups
    await db.commit()
    await recalculate_peers_for_user(db, user.id)

    response = await render_users_table_paginated(
        request,
        db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )

    response.headers["HX-Trigger"] = "usersCloseDrawer"
    return response


@ui_fragments_router.get("/ui/users/{user_id}/password", response_class=HTMLResponse)
async def ui_user_password_form(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>User not found.</div>",
            status_code=404,
        )

    return templates.TemplateResponse(
        request=request,
        name="user_password_form.html",
        context={
            "user": user,
            "form_action": f"/ui/users/{user_id}/password",
        },
    )


@ui_fragments_router.post("/ui/users/{user_id}/password", response_class=HTMLResponse)
async def ui_user_password_submit(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(get_db),
):
    form = await request.form()

    new_password = str(form.get("new_password", "")).strip()
    confirm_password = str(form.get("confirm_password", "")).strip()

    if len(new_password) < 8:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Password must be at least 8 characters.</div>",
            status_code=200,
        )

    if new_password != confirm_password:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Passwords do not match.</div>",
            status_code=200,
        )

    user = await db.get(User, user_id)
    if not user:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>User not found.</div>",
            status_code=404,
        )

    user.hashed_password = hash_password(new_password)
    user.token_version = (user.token_version or 0) + 1

    await db.execute(
        update(AuthSession)
        .where(
            AuthSession.user_id == user_id,
            AuthSession.is_revoked.is_(False),
        )
        .values(is_revoked=True)
    )

    await db.commit()

    response = HTMLResponse(
        "<div class='px-4 py-3 text-sm text-emerald-400'>Password updated. All sessions revoked.</div>"
    )
    response.headers["HX-Trigger"] = "users:passwordChanged"
    return response


async def render_users_table_paginated(
    request: Request,
    db: AsyncSession,
    *,
    page: int = 1,
    limit: int = 20,
    status_filter: str = "active",
) -> HTMLResponse:
    page = max(page, 1)
    if limit not in {5, 10, 20, 50, 100}:
        limit = 20

    status_filter = (status_filter or "active").strip().lower()
    if status_filter not in {"active", "inactive", "all"}:
        status_filter = "active"

    query = select(User)
    count_query = select(func.count()).select_from(User)

    if status_filter == "active":
        query = query.where(User.is_active.is_(True))
        count_query = count_query.where(User.is_active.is_(True))
    elif status_filter == "inactive":
        query = query.where(User.is_active.is_(False))
        count_query = count_query.where(User.is_active.is_(False))

    total = (await db.execute(count_query)).scalar() or 0
    total_pages = max((total + limit - 1) // limit, 1)

    if page > total_pages:
        page = total_pages

    query = query.order_by(User.id.asc()).offset((page - 1) * limit).limit(limit)
    result = await db.execute(query)
    users = result.scalars().all()

    user_rows = [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "is_active": u.is_active,
            "is_admin": u.is_admin,
            "created_at": u.created_at.strftime("%Y-%m-%d %H:%M") if u.created_at else "—",
        }
        for u in users
    ]

    html = templates.get_template("users_table_paginated.html").render(
        users=user_rows,
        request=request,
        filters={
            "page": page,
            "limit": limit,
            "status": status_filter,
            "total": total,
            "total_pages": total_pages,
        },
    )
    return HTMLResponse(html)


@ui_fragments_router.post("/ui/users/{user_id}/toggle-active", response_class=HTMLResponse)
async def ui_user_toggle_active(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>User not found.</div>",
            status_code=404,
        )

    user.is_active = not user.is_active

    if not user.is_active:
        await db.execute(
            update(AuthSession)
            .where(
                AuthSession.user_id == user_id,
                AuthSession.is_revoked.is_(False),
            )
            .values(is_revoked=True)
        )

    await db.commit()

    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = request.query_params.get("status", "active")

    return await render_users_table_paginated(
        request,
        db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


@ui_fragments_router.post("/ui/users/{user_id}/toggle-admin", response_class=HTMLResponse)
async def ui_user_toggle_admin(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>User not found.</div>",
            status_code=404,
        )

    user.is_admin = not user.is_admin
    await db.commit()

    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = request.query_params.get("status", "active")

    return await render_users_table_paginated(
        request,
        db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


@ui_fragments_router.get("/ui/users/new", response_class=HTMLResponse)
async def ui_user_new_form(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="user_form.html",
        context={
            "user": None,
            "form_action": "/ui/users/create",
            "submit_label": "Create user",
            "page": int(request.query_params.get("page", 1) or 1),
            "limit": int(request.query_params.get("limit", 20) or 20),
            "status": request.query_params.get("status", "active"),
        },
    )


@ui_fragments_router.post("/ui/users/create", response_class=HTMLResponse)
async def ui_user_create_submit(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    form = await request.form()

    page = int(form.get("page", 1) or 1)
    limit = int(form.get("limit", 20) or 20)
    status_filter = str(form.get("status", "active") or "active")

    username = str(form.get("username", "")).strip()
    email = str(form.get("email", "")).strip()
    password = str(form.get("password", "")).strip()
    is_admin = form.get("is_admin") == "on"
    is_active = form.get("is_active") == "on"

    if not username or not email or not password:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Username, email, and password are required.</div>",
            status_code=400,
        )

    existing_username = await db.execute(
        select(User).where(User.username == username)
    )
    if existing_username.scalar_one_or_none():
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Username already exists.</div>",
            status_code=409,
        )

    existing_email = await db.execute(
        select(User).where(User.email == email)
    )
    if existing_email.scalar_one_or_none():
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Email already exists.</div>",
            status_code=409,
        )

    user = User(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        is_active=is_active,
        is_admin=is_admin,
    )
    db.add(user)
    await db.commit()

    response = await render_users_table_paginated(
        request,
        db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )

    response.headers["HX-Trigger"] = "usersCloseDrawer"
    return response


@ui_fragments_router.get("/ui/users/{user_id}/delete-confirm", response_class=HTMLResponse)
async def ui_user_delete_confirm(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(get_db),
):
    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")

    result = await db.execute(
        select(User)
        .options(selectinload(User.groups), selectinload(User.peers))
        .where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    if not user:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>User not found.</div>",
            status_code=404,
        )

    direct_policy_count = (
        await db.execute(
            select(func.count()).select_from(Policy).where(Policy.user_id == user_id)
        )
    ).scalar_one()

    active_peer_count = sum(
        1 for peer in user.peers
        if peer.provisioning_status != ProvisioningStatus.removed
    )

    return templates.TemplateResponse(
        request=request,
        name="user_delete_confirm.html",
        context={
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "group_count": len(user.groups),
                "removed_peer_count": len(user.peers) - active_peer_count,
                "active_peer_count": active_peer_count,
                "direct_policy_count": direct_policy_count,
            },
            "can_delete": active_peer_count == 0 and direct_policy_count == 0,
            "page": page,
            "limit": limit,
            "status": status_filter,
        },
    )


@ui_fragments_router.delete("/ui/users/{user_id}", response_class=HTMLResponse)
async def ui_user_delete(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(get_db),
):
    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")

    result = await db.execute(
        select(User)
        .options(selectinload(User.groups), selectinload(User.peers))
        .where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    if not user:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>User not found.</div>",
            status_code=404,
        )

    direct_policy_count = (
        await db.execute(
            select(func.count()).select_from(Policy).where(Policy.user_id == user_id)
        )
    ).scalar_one()
    active_peer_count = sum(
        1 for peer in user.peers
        if peer.provisioning_status != ProvisioningStatus.removed
    )

    if direct_policy_count or active_peer_count:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>"
            "User cannot be deleted while active, pending, or failed peers "
            "or direct policies still exist."
            "</div>",
            status_code=409,
        )

    await db.execute(delete(AuthSession).where(AuthSession.user_id == user_id))
    await db.execute(
        delete(Peer).where(
            Peer.user_id == user_id,
            Peer.provisioning_status == ProvisioningStatus.removed,
        )
    )

    user.groups = []
    await db.flush()
    await db.delete(user)
    await db.commit()

    return await render_users_table_paginated(
        request,
        db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


def build_group_form_state(group: Group | None = None) -> dict:
    if group is None:
        return {"name": "", "description": "", "is_active": True, "user_ids": []}
    return {
        "id": group.id,
        "name": group.name or "",
        "description": group.description or "",
        "is_active": bool(group.is_active),
        "user_ids": [u.id for u in group.users] if group.users else [],
    }


def group_form_response(
    request: Request, *, form_title: str, form_action: str, submit_label: str,
    group: dict, users: list, error_message: str = "",
    page: int = 1, limit: int = 20, status_filter: str = "active",
    status_code: int = status.HTTP_200_OK,
):
    response = templates.TemplateResponse(
        request=request, name="group_form.html",
        context={
            "form_title": form_title, "form_action": form_action,
            "submit_label": submit_label, "group": group, "users": users,
            "error_message": error_message, "page": page, "limit": limit,
            "status": status_filter,
        },
        status_code=status_code,
    )
    response.headers["HX-Retarget"] = "#modal-root"
    return response


async def render_groups_table_paginated(
    request: Request, db: AsyncSession,
    page: int = 1, limit: int = 20, status_filter: str = "active",
) -> HTMLResponse:
    page = max(page, 1)
    if limit not in {5, 10, 20, 50, 100}:
        limit = 20
    status_filter = (status_filter or "active").strip().lower()
    if status_filter not in {"active", "inactive", "all"}:
        status_filter = "active"

    query = select(Group).options(
        selectinload(Group.users),
        selectinload(Group.policies),
    )
    count_query = select(func.count()).select_from(Group)

    if status_filter == "active":
        query = query.where(Group.is_active.is_(True))
        count_query = count_query.where(Group.is_active.is_(True))
    elif status_filter == "inactive":
        query = query.where(Group.is_active.is_(False))
        count_query = count_query.where(Group.is_active.is_(False))

    total = (await db.execute(count_query)).scalar() or 0
    total_pages = max((total + limit - 1) // limit, 1)
    if page > total_pages:
        page = total_pages

    query = query.order_by(Group.name.asc()).offset((page - 1) * limit).limit(limit)
    result = await db.execute(query)
    groups = result.scalars().unique().all()

    group_rows = [
        {
            "id": g.id,
            "name": g.name,
            "description": g.description or "—",
            "member_count": len(g.users),
            "members_preview": [
                (u.username or u.email or f"user-{u.id}")
                for u in (g.users[:3] if g.users else [])
            ],
            "policy_count": len(getattr(g, "policies", []) or []),
            "is_active": bool(g.is_active),
            "created_at": getattr(g, "created_at", None),
        }
        for g in groups
    ]

    html = templates.get_template("groups_table_paginated.html").render(
        groups=group_rows, request=request, page=page, limit=limit,
        status=status_filter, total=total, total_pages=total_pages,
    )
    return HTMLResponse(html)


@ui_fragments_router.get("/ui/groups/table", response_class=HTMLResponse)
async def ui_groups_table(
    request: Request, page: int = 1, limit: int = 20, status: str = "active",
    db: AsyncSession = Depends(get_db),
):
    return await render_groups_table_paginated(request, db, page, limit, status)


@ui_fragments_router.get("/ui/groups/new", response_class=HTMLResponse)
async def ui_group_new_form(request: Request, db: AsyncSession = Depends(get_db)):
    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")
    users_result = await db.execute(select(User).order_by(User.username.asc()))
    users = [{"id": u.id, "label": u.username or u.email} for u in users_result.scalars().all()]
    return group_form_response(
        request, form_title="New group", form_action="/ui/groups/create",
        submit_label="Create group", group=build_group_form_state(), users=users,
        page=page, limit=limit, status_filter=status_filter,
    )


@ui_fragments_router.post("/ui/groups/create", response_class=HTMLResponse)
async def ui_group_create_submit(request: Request, db: AsyncSession = Depends(get_db)):
    form = await request.form()
    page = int(str(form.get("page", 1) or 1))
    limit = int(str(form.get("limit", 20) or 20))
    status_filter = str(form.get("status", "active") or "active")
    name = str(form.get("name", "")).strip()
    description = str(form.get("description", "")).strip() or None
    user_ids = [int(v) for v in form.getlist("user_ids") if str(v).isdigit()]

    users_result = await db.execute(select(User).order_by(User.username.asc()))
    all_users = [{"id": u.id, "label": u.username or u.email} for u in users_result.scalars().all()]

    try:
        group = await create_group(db, GroupCreate(name=name, description=description))

        # Explicitly load the relationship before assignment. This prevents
        # SQLAlchemy async lazy-loading (MissingGreenlet) on group.users.
        await db.refresh(group, attribute_names=["users"])

        if user_ids:
            members_result = await db.execute(select(User).where(User.id.in_(user_ids)))
            group.users = list(members_result.scalars().all())

        await db.commit()
    except ValueError as exc:
        return group_form_response(
            request, form_title="New group", form_action="/ui/groups/create",
            submit_label="Create group",
            group={"name": name, "description": description, "is_active": True, "user_ids": user_ids},
            users=all_users, error_message=str(exc),
            page=page, limit=limit, status_filter=status_filter, status_code=200,
        )

    return await render_groups_table_paginated(request, db, page, limit, status_filter)


@ui_fragments_router.get("/ui/groups/{group_id}/edit", response_class=HTMLResponse)
async def ui_group_edit_form(request: Request, group_id: int, db: AsyncSession = Depends(get_db)):
    group = await get_group_with_users(db, group_id)
    if not group:
        return HTMLResponse("<div class='px-4 py-3 text-sm text-rose-300'>Group not found.</div>", status_code=404)

    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")

    users_result = await db.execute(select(User).order_by(User.username.asc()))
    all_users = [{"id": u.id, "label": u.username or u.email} for u in users_result.scalars().all()]

    return group_form_response(
        request, form_title="Edit group", form_action=f"/ui/groups/{group_id}/edit",
        submit_label="Save changes", group=build_group_form_state(group), users=all_users,
        page=page, limit=limit, status_filter=status_filter,
    )


@ui_fragments_router.post("/ui/groups/{group_id}/edit", response_class=HTMLResponse)
async def ui_group_edit_submit(request: Request, group_id: int, db: AsyncSession = Depends(get_db)):
    form = await request.form()
    page = int(str(form.get("page", 1) or 1))
    limit = int(str(form.get("limit", 20) or 20))
    status_filter = str(form.get("status", "active") or "active")
    name = str(form.get("name", "")).strip()
    description = str(form.get("description", "")).strip() or None
    is_active = form.get("is_active") == "on"
    user_ids = [int(v) for v in form.getlist("user_ids") if str(v).isdigit()]

    try:
        await update_group(db, group_id, GroupUpdate(name=name, description=description, is_active=is_active))
        group = await get_group_with_users(db, group_id)
        members_result = await db.execute(select(User).where(User.id.in_(user_ids))) if user_ids else None
        group.users = list(members_result.scalars().all()) if members_result else []
        await db.commit()
    except ValueError as exc:
        users_result = await db.execute(select(User).order_by(User.username.asc()))
        all_users = [{"id": u.id, "label": u.username or u.email} for u in users_result.scalars().all()]
        return group_form_response(
            request, form_title="Edit group", form_action=f"/ui/groups/{group_id}/edit",
            submit_label="Save changes",
            group={"id": group_id, "name": name, "description": description, "is_active": is_active, "user_ids": user_ids},
            users=all_users, error_message=str(exc),
            page=page, limit=limit, status_filter=status_filter, status_code=200,
        )

    return await render_groups_table_paginated(request, db, page, limit, status_filter)


@ui_fragments_router.post("/ui/groups/{group_id}/enable", response_class=HTMLResponse)
async def ui_group_enable(request: Request, group_id: int, db: AsyncSession = Depends(get_db)):
    group = await get_group_with_users(db, group_id)
    if not group:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Group not found.</div>",
            status_code=404,
        )

    group.is_active = True
    await db.commit()

    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")
    return await render_groups_table_paginated(request, db, page, limit, status_filter)


@ui_fragments_router.post("/ui/groups/{group_id}/disable", response_class=HTMLResponse)
async def ui_group_disable(request: Request, group_id: int, db: AsyncSession = Depends(get_db)):
    group = await get_group_with_users(db, group_id)
    if not group:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Group not found.</div>",
            status_code=404,
        )

    group.is_active = False
    await db.commit()

    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")
    return await render_groups_table_paginated(request, db, page, limit, status_filter)


@ui_fragments_router.post("/ui/groups/{group_id}/delete", response_class=HTMLResponse)
async def ui_group_delete(request: Request, group_id: int, db: AsyncSession = Depends(get_db)):
    group = await get_group_with_users(db, group_id)
    if not group:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Group not found.</div>",
            status_code=404,
        )

    policy_count = (
        await db.execute(
            select(func.count())
            .select_from(Policy)
            .where(Policy.group_id == group_id)
        )
    ).scalar_one()

    if policy_count:
        policy_label = "policy" if policy_count == 1 else "policies"
        return HTMLResponse(
            f"<div class='fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4'>"
            f"  <div class='w-full max-w-md rounded-lg border border-amber-700 bg-slate-950 p-6 shadow-xl'>"
            f"    <h3 class='text-lg font-semibold text-amber-200'>Cannot delete group</h3>"
            f"    <p class='mt-3 text-sm text-slate-300'>"
            f"      This group is used by {policy_count} {policy_label}. "
            f"      Remove or reassign the related policies before deleting it."
            f"    </p>"
            f"    <div class='mt-5 flex justify-end gap-3'>"
            f"      <a href='/policies?group_id={group_id}' "
            f"         class='rounded-md bg-cyan-700 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-600'>"
            f"        View {policy_count} related {policy_label}"
            f"      </a>"
            f"      <button type='button' "
            f"              class='rounded-md bg-slate-700 px-4 py-2 text-sm text-white hover:bg-slate-600' "
            f"              onclick=\"document.getElementById('modal-root').innerHTML=''\">"
            f"        Close"
            f"      </button>"
            f"    </div>"
            f"  </div>"
            f"</div>",
            headers={"HX-Retarget": "#modal-root", "HX-Reswap": "innerHTML"},
        )

    await db.delete(group)
    await db.commit()

    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")
    return await render_groups_table_paginated(request, db, page, limit, status_filter)


@ui_fragments_router.post("/ui/resources/{resource_id}/enable", response_class=HTMLResponse)
async def ui_resource_enable(
    request: Request,
    resource_id: int,
    db: AsyncSession = Depends(get_db),
):
    resource = await db.get(Resource, resource_id)
    if not resource:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Resource not found.</div>",
            status_code=404,
        )

    if not resource.is_active:
        resource.is_active = True
        await db.commit()
        await db.refresh(resource)
        await recalculate_peers_for_resource(db, resource)

    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "inactive") or "inactive")

    return await render_resources_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


@ui_fragments_router.post("/ui/resources/{resource_id}/permanent-delete", response_class=HTMLResponse)
async def ui_resource_permanent_delete(
    request: Request,
    resource_id: int,
    db: AsyncSession = Depends(get_db),
):
    resource = await db.get(Resource, resource_id)
    if not resource:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Resource not found.</div>",
            status_code=404,
        )

    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "inactive") or "inactive")

    if resource.is_active:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-amber-200'>"
            "Disable this resource before deleting it permanently."
            "</div>",
            status_code=400,
        )

    policy_count = (
        await db.execute(
            select(func.count())
            .select_from(Policy)
            .where(Policy.resource_id == resource_id)
        )
    ).scalar_one()

    if policy_count:
        policy_label = "policy" if policy_count == 1 else "policies"
        return HTMLResponse(
            f"<div class='fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4'>"
            f"  <div class='w-full max-w-md rounded-lg border border-amber-700 bg-slate-950 p-6 shadow-xl'>"
            f"    <h3 class='text-lg font-semibold text-amber-200'>Cannot delete resource</h3>"
            f"    <p class='mt-3 text-sm text-slate-300'>"
            f"      This resource is used by {policy_count} {policy_label}. "
            f"      Remove or reassign the related policies before deleting it permanently."
            f"    </p>"
            f"    <div class='mt-5 flex flex-wrap justify-end gap-3'>"
            f"      <a href='/policies?resource_id={resource_id}' "
            f"         class='rounded-md bg-cyan-700 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-600'>"
            f"        View {policy_count} related {policy_label}"
            f"      </a>"
            f"      <button type='button' "
            f"              class='rounded-md bg-slate-700 px-4 py-2 text-sm text-white hover:bg-slate-600' "
            f"              onclick=\"document.getElementById('modal-root').innerHTML=''\">"
            f"        Close"
            f"      </button>"
            f"    </div>"
            f"  </div>"
            f"</div>",
            headers={"HX-Retarget": "#modal-root", "HX-Reswap": "innerHTML"},
        )

    await db.delete(resource)
    await db.commit()

    return await render_resources_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


async def render_tenants_table_paginated(
    request: Request,
    db: AsyncSession,
    page: int = 1,
    limit: int = 20,
    status_filter: str = "active",
) -> HTMLResponse:
    page = max(page, 1)

    if limit not in {5, 10, 20, 50, 100}:
        limit = 20

    status_filter = (status_filter or "active").strip().lower()
    if status_filter not in {"active", "inactive", "all"}:
        status_filter = "active"

    query = select(Tenant)
    count_query = select(func.count()).select_from(Tenant)

    if status_filter == "active":
        query = query.where(Tenant.is_active.is_(True))
        count_query = count_query.where(Tenant.is_active.is_(True))
    elif status_filter == "inactive":
        query = query.where(Tenant.is_active.is_(False))
        count_query = count_query.where(Tenant.is_active.is_(False))

    total = (await db.execute(count_query)).scalar() or 0
    total_pages = max((total + limit - 1) // limit, 1)

    if page > total_pages:
        page = total_pages

    query = query.order_by(Tenant.id.asc()).offset((page - 1) * limit).limit(limit)
    result = await db.execute(query)
    tenants = result.scalars().all()

    tenant_rows = [
        {
            "id": t.id,
            "name": t.name,
            "slug": getattr(t, "slug", None),
            "is_active": getattr(t, "is_active", True),
            "created_at": t.created_at.strftime("%Y-%m-%d %H:%M") if getattr(t, "created_at", None) else "—",
        }
        for t in tenants
    ]

    html = templates.get_template("tenants_table_paginated.html").render(
        tenants=tenant_rows,
        request=request,
        filters={
            "page": page,
            "limit": limit,
            "status": status_filter,
            "total": total,
            "total_pages": total_pages,
        },
    )
    return HTMLResponse(html)


@ui_fragments_router.get("/ui/tenants/table", response_class=HTMLResponse)
async def ui_tenants_table(
    request: Request,
    page: int = 1,
    limit: int = 20,
    status: str = "active",
    db: AsyncSession = Depends(get_db),
):
    return await render_tenants_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status,
    )


@ui_fragments_router.get("/ui/tenants/new", response_class=HTMLResponse)
async def ui_tenant_new_form(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="tenant_form.html",
        context={
            "tenant": None,
            "form_title": "New tenant",
            "form_action": "/ui/tenants/create",
            "submit_label": "Create tenant",
        },
    )


@ui_fragments_router.post("/ui/tenants/create", response_class=HTMLResponse)
async def ui_tenant_create(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    form = await request.form()

    name = str(form.get("name", "")).strip()
    slug = str(form.get("slug", "")).strip()
    isactive = form.get("isactive") == "on"

    if not name:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Tenant name is required.</div>",
            status_code=400,
        )

    tenant = Tenant(
        name=name,
        slug=slug or None,
        is_active=isactive,
    )
    db.add(tenant)
    await db.commit()

    page = int(form.get("page", 1) or 1)
    limit = int(form.get("limit", 20) or 20)
    status_filter = str(form.get("status", "active") or "active")

    response = await render_tenants_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )
    response.headers["HX-Retarget"] = "#tenants-table"
    response.headers["HX-Reswap"] = "innerHTML"
    response.headers["HX-Trigger"] = "tenantcreated"
    return response


@ui_fragments_router.get("/ui/tenants/{tenant_id}/edit", response_class=HTMLResponse)
async def ui_tenant_edit_form(
    request: Request,
    tenant_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Tenant not found.</div>",
            status_code=404,
        )

    return templates.TemplateResponse(
        request=request,
        name="tenant_form.html",
        context={
            "tenant": tenant,
            "form_title": "Edit tenant",
            "form_action": f"/ui/tenants/{tenant_id}/edit",
            "submit_label": "Save changes",
        },
    )


@ui_fragments_router.post("/ui/tenants/{tenant_id}/edit", response_class=HTMLResponse)
async def ui_tenant_edit(
    request: Request,
    tenant_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Tenant not found.</div>",
            status_code=404,
        )

    form = await request.form()

    tenant.name = str(form.get("name", "")).strip()
    tenant.slug = str(form.get("slug", "")).strip() or None
    tenant.is_active = form.get("isactive") == "on"

    await db.commit()

    page = int(form.get("page", 1) or 1)
    limit = int(form.get("limit", 20) or 20)
    status_filter = str(form.get("status", "active") or "active")

    response = await render_tenants_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )
    response.headers["HX-Retarget"] = "#tenants-table"
    response.headers["HX-Reswap"] = "innerHTML"
    response.headers["HX-Trigger"] = "tenantupdated"
    return response


@ui_fragments_router.post("/ui/tenants/{tenant_id}/delete", response_class=HTMLResponse)
async def ui_tenant_delete(
    request: Request,
    tenant_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Tenant not found.</div>",
            status_code=404,
        )

    await db.delete(tenant)
    await db.commit()

    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")

    return await render_tenants_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


@ui_fragments_router.post("/ui/tenants/{tenant_id}/toggle", response_class=HTMLResponse)
async def ui_tenants_toggle(
    request: Request,
    tenant_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        return HTMLResponse(
            '<div class="px-4 py-3 text-sm text-rose-300">Tenant not found.</div>',
            status_code=404,
        )

    tenant.is_active = not tenant.is_active
    await db.commit()

    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")

    return await render_tenants_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


async def render_policies_table_paginated(
    request: Request,
    db: AsyncSession,
    page: int = 1,
    limit: int = 20,
    status_filter: str = "active",
    group_id: int | None = None,
) -> HTMLResponse:
    page = max(page, 1)

    if limit not in {5, 10, 20, 50, 100}:
        limit = 20

    status_filter = (status_filter or "active").strip().lower()
    if status_filter not in {"active", "inactive", "all"}:
        status_filter = "active"

    query = (
        select(Policy)
        .options(
            selectinload(Policy.user),
            selectinload(Policy.group),
            selectinload(Policy.resource),
        )
    )
    count_query = select(func.count()).select_from(Policy)

    if status_filter == "active":
        query = query.where(Policy.is_active.is_(True))
        count_query = count_query.where(Policy.is_active.is_(True))
    elif status_filter == "inactive":
        query = query.where(Policy.is_active.is_(False))
        count_query = count_query.where(Policy.is_active.is_(False))

    selected_group_name = None
    if group_id is not None:
        query = query.where(Policy.group_id == group_id)
        count_query = count_query.where(Policy.group_id == group_id)
        selected_group = await db.get(Group, group_id)
        selected_group_name = selected_group.name if selected_group else f"Group #{group_id}"

    total = (await db.execute(count_query)).scalar() or 0
    total_pages = max((total + limit - 1) // limit, 1)

    if page > total_pages:
        page = total_pages

    query = query.order_by(Policy.id.asc()).offset((page - 1) * limit).limit(limit)
    result = await db.execute(query)
    policies = result.scalars().all()

    policy_rows = []
    for p in policies:
        subject_type = "user" if getattr(p, "user_id", None) else "group" if getattr(p, "group_id", None) else "unknown"
        subject_name = None

        if getattr(p, "user", None):
            subject_name = p.user.username or p.user.email or str(p.user.id)
        elif getattr(p, "group", None):
            subject_name = p.group.name or str(p.group.id)

        resource_name = p.resource.name if getattr(p, "resource", None) else "—"

        # Новый блок: форматируем conditions для таблицы
        raw_conditions = getattr(p, "conditions", None)
        raw_conditions = "" if raw_conditions is None else str(raw_conditions).strip()

        if not raw_conditions:
            conditions_label = raw_conditions if raw_conditions else "{}"
        else:
                # При желании обрезаем длинные значения
                conditions_label = raw_conditions if len(raw_conditions) <= 80 else raw_conditions[:77] + "..."

        policy_rows.append(
            {
                "id": p.id,
                "name": p.name,
                "description": getattr(p, "description", "") or "",
                "subject_type": subject_type,
                "subject_label": subject_name or "—",
                "resource_label": resource_name,
                "effect": getattr(p, "effect", "allow"),
                "priority": getattr(p, "priority", 100),
                "created_at": getattr(p, "created_at", None),
                "is_active": getattr(p, "is_active", True),
                "conditions_label": conditions_label,
            }
        )

    html = templates.get_template("policies_table.html").render(
        policies=policy_rows,
        request=request,
        page=page,
        limit=limit,
        status=status_filter,
        total=total,
        total_pages=total_pages,
        group_id=group_id,
        selected_group_name=selected_group_name,
        filters={
            "page": page,
            "limit": limit,
            "status": status_filter,
            "group_id": group_id,
            "total": total,
            "total_pages": total_pages,
        },
    )
    return HTMLResponse(html)


@ui_fragments_router.get("/ui/policies/table", response_class=HTMLResponse)
async def ui_policies_table(
    request: Request,
    page: int = 1,
    limit: int = 20,
    status: str = "active",
    group_id: int | None = None,
    db: AsyncSession = Depends(get_db),
):
    return await render_policies_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status,
        group_id=group_id,
    )


@ui_fragments_router.get("/ui/policies/new", response_class=HTMLResponse)
async def ui_policy_new_form(
    request: Request,
    resources_users_groups: tuple[list[dict], list[dict], list[dict]] = Depends(load_policy_form_options),
):
    resources, users, groups = resources_users_groups
    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")

    policy = build_policy_form_state(
        name="",
        description="",
        subject_type="user",
        user_id=None,
        group_id=None,
        resource_id=None,
        effect="allow",
        priority=100,
        conditions="{}",
    )
    return policy_form_response(
        request,
        form_title="New policy",
        form_action=f"/ui/policies/create?page={page}&limit={limit}&status={status_filter}",
        submit_label="Create policy",
        policy=policy,
        resources=resources,
        users=users,
        groups=groups,
        error_message="",
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


@ui_fragments_router.post("/ui/policies/create", response_class=HTMLResponse)
async def ui_policy_create_submit(
    request: Request,
    db: AsyncSession = Depends(get_db),
    resources_users_groups: tuple[list[dict], list[dict], list[dict]] = Depends(load_policy_form_options),
):
    resources, users, groups = resources_users_groups
    form = await request.form()

    page = int(str(form.get("page", 1) or 1))
    limit = int(str(form.get("limit", 20) or 20))
    status_filter = str(form.get("status", "active") or "active")

    name = str(form.get("name", "")).strip()
    description = str(form.get("description", "")).strip()
    subject_type = str(form.get("subject_type", "user")).strip() or "user"
    user_id = form.get("user_id")
    group_id = form.get("group_id")
    resource_id = form.get("resource_id")
    effect = str(form.get("effect", "allow")).strip() or "allow"
    priority_raw = str(form.get("priority", "100")).strip() or "100"

    try:
        priority = int(priority_raw)
    except ValueError:
        priority = 100

    conditions = str(form.get("conditions", "")).strip()
    if not conditions:
        conditions = "{}"

    try:
        policy_in = {
            "name": name,
            "description": description or None,
            "user_id": parse_optional_int(user_id) if subject_type == "user" else None,
            "group_id": parse_optional_int(group_id) if subject_type == "group" else None,
            "resource_id": parse_optional_int(resource_id),
            "effect": effect,
            "priority": priority,
            "conditions": conditions,
        }
        created_policy = await create_policy(db, policy_in)
        await recalculate_users_after_policy_change(
            db,
            await get_affected_user_ids_for_ui_policy(db, created_policy),
        )
    except Exception as exc:
        return policy_form_response(
            request,
            form_title="New policy",
            form_action=f"/ui/policies/create?page={page}&limit={limit}&status={status_filter}",
            submit_label="Create policy",
            policy=build_policy_form_state(
                name=name,
                description=description,
                subject_type=subject_type,
                user_id=user_id,
                group_id=group_id,
                resource_id=resource_id,
                effect=effect,
                priority=priority,
                conditions=conditions,
            ),
            resources=resources,
            users=users,
            groups=groups,
            error_message=str(exc),
            page=page,
            limit=limit,
            status_filter=status_filter,
        )

    response = await render_policies_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )
    return response


@ui_fragments_router.get("/ui/policies/{policy_id}/edit", response_class=HTMLResponse)
async def ui_policy_edit_form(
    request: Request,
    policy_id: int,
    db: AsyncSession = Depends(get_db),
    resources_users_groups: tuple[list[dict], list[dict], list[dict]] = Depends(load_policy_form_options),
):
    resources, users, groups = resources_users_groups

    result = await db.execute(
        select(Policy)
        .options(
            selectinload(Policy.user),
            selectinload(Policy.group),
            selectinload(Policy.resource),
        )
        .where(Policy.id == policy_id)
    )
    policy_obj = result.scalar_one_or_none()
    if not policy_obj:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Policy not found.</div>",
            status_code=404,
        )

    policy = build_policy_form_state(
        name=policy_obj.name,
        description=policy_obj.description or "",
        subject_type="user" if policy_obj.user_id else "group",
        user_id=policy_obj.user_id,
        group_id=policy_obj.group_id,
        resource_id=policy_obj.resource_id,
        effect=policy_obj.effect,
        priority=policy_obj.priority,
        conditions=json.dumps(policy_obj.conditions or {}, ensure_ascii=False, indent=2),
        policy_id=policy_obj.id,
    )

    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")

    return policy_form_response(
        request,
        form_title="Edit policy",
        form_action=f"/ui/policies/{policy_id}/edit?page={page}&limit={limit}&status={status_filter}",
        submit_label="Save changes",
        policy=policy,
        resources=resources,
        users=users,
        groups=groups,
        error_message="",
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


@ui_fragments_router.post("/ui/policies/{policy_id}/edit", response_class=HTMLResponse)
async def ui_policy_edit_submit(
    request: Request,
    policy_id: int,
    db: AsyncSession = Depends(get_db),
    resources_users_groups: tuple[list[dict], list[dict], list[dict]] = Depends(load_policy_form_options),
):
    resources, users, groups = resources_users_groups
    form = await request.form()

    page = int(str(form.get("page", 1) or 1))
    limit = int(str(form.get("limit", 20) or 20))
    status_filter = str(form.get("status", "active") or "active")

    name = str(form.get("name", "")).strip()
    description = str(form.get("description", "")).strip()
    subject_type = str(form.get("subject_type", "user")).strip() or "user"
    user_id = form.get("user_id")
    group_id = form.get("group_id")
    resource_id = form.get("resource_id")
    effect = str(form.get("effect", "allow")).strip() or "allow"
    priority_raw = str(form.get("priority", "100")).strip() or "100"

    try:
        priority = int(priority_raw)
    except ValueError:
        priority = 100

    conditions = str(form.get("conditions", "")).strip()
    if not conditions:
        conditions = "{}"

    try:
        policy_in = {
            "name": name,
            "description": description or None,
            "user_id": parse_optional_int(user_id) if subject_type == "user" else None,
            "group_id": parse_optional_int(group_id) if subject_type == "group" else None,
            "resource_id": parse_optional_int(resource_id),
            "effect": effect,
            "priority": priority,
            "conditions": conditions,
        }
        previous_policy = await db.get(Policy, policy_id)
        if not previous_policy:
            raise HTTPException(status_code=404, detail="Policy not found")

        affected_user_ids = await get_affected_user_ids_for_ui_policy(
            db,
            previous_policy,
        )

        updated_policy = await update_policy(db, policy_id, policy_in)

        affected_user_ids.update(
            await get_affected_user_ids_for_ui_policy(db, updated_policy)
        )
        await recalculate_users_after_policy_change(db, affected_user_ids)
    except Exception as exc:
        return policy_form_response(
            request,
            form_title="Edit policy",
            form_action=f"/ui/policies/{policy_id}/edit?page={page}&limit={limit}&status={status_filter}",
            submit_label="Save changes",
            policy=build_policy_form_state(
                name=name,
                description=description,
                subject_type=subject_type,
                user_id=user_id,
                group_id=group_id,
                resource_id=resource_id,
                effect=effect,
                priority=priority,
                conditions=conditions,
                policy_id=policy_id,
            ),
            resources=resources,
            users=users,
            groups=groups,
            error_message=str(exc),
            page=page,
            limit=limit,
            status_filter=status_filter,
        )

    response = await render_policies_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )
    return response


@ui_fragments_router.post("/ui/policies/{policy_id}/disable", response_class=HTMLResponse)
async def ui_policy_disable(
    request: Request,
    policy_id: int,
    db: AsyncSession = Depends(get_db),
):
    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")

    policy = await db.get(Policy, policy_id)
    if not policy:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Policy not found.</div>",
            status_code=404,
        )

    affected_user_ids = await get_affected_user_ids_for_ui_policy(db, policy)
    policy.is_active = False
    await db.commit()
    await recalculate_users_after_policy_change(db, affected_user_ids)

    return await render_policies_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


@ui_fragments_router.post("/ui/policies/{policy_id}/enable", response_class=HTMLResponse)
async def ui_policy_enable(
    request: Request,
    policy_id: int,
    db: AsyncSession = Depends(get_db),
):
    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")

    policy = await db.get(Policy, policy_id)
    if not policy:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Policy not found.</div>",
            status_code=404,
        )

    policy.is_active = True
    await db.commit()
    await recalculate_users_after_policy_change(
        db,
        await get_affected_user_ids_for_ui_policy(db, policy),
    )

    return await render_policies_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


@ui_fragments_router.get("/ui/policies/{policy_id}/delete-confirm", response_class=HTMLResponse)
async def ui_policy_delete_confirm(
    request: Request,
    policy_id: int,
    db: AsyncSession = Depends(get_db),
):
    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")

    result = await db.execute(
        select(Policy)
        .options(
            selectinload(Policy.user),
            selectinload(Policy.group),
            selectinload(Policy.resource),
        )
        .where(Policy.id == policy_id)
    )
    policy = result.scalar_one_or_none()

    if not policy:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Policy not found.</div>",
            status_code=404,
        )

    if policy.user:
        subject = policy.user.username or policy.user.email or str(policy.user.id)
    elif policy.group:
        subject = policy.group.name or str(policy.group.id)
    else:
        subject = "Global policy"

    resource = policy.resource.name if policy.resource else "—"
    effect = getattr(policy.effect, "value", policy.effect)

    return templates.TemplateResponse(
        request=request,
        name="policy_delete_confirm.html",
        context={
            "policy": {
                "id": policy.id,
                "name": policy.name,
                "subject": subject,
                "resource": resource,
                "effect": effect,
                "priority": policy.priority,
            },
            "page": page,
            "limit": limit,
            "status": status_filter,
        },
    )


@ui_fragments_router.delete("/ui/policies/{policy_id}", response_class=HTMLResponse)
async def ui_policy_delete(
    request: Request,
    policy_id: int,
    db: AsyncSession = Depends(get_db),
):
    page = int(request.query_params.get("page", 1) or 1)
    limit = int(request.query_params.get("limit", 20) or 20)
    status_filter = str(request.query_params.get("status", "active") or "active")

    policy = await db.get(Policy, policy_id)
    if not policy:
        return HTMLResponse(
            "<div class='px-4 py-3 text-sm text-rose-300'>Policy not found.</div>",
            status_code=404,
        )

    affected_user_ids = await get_affected_user_ids_for_ui_policy(db, policy)
    await db.delete(policy)
    await db.commit()
    await recalculate_users_after_policy_change(db, affected_user_ids)

    return await render_policies_table_paginated(
        request=request,
        db=db,
        page=page,
        limit=limit,
        status_filter=status_filter,
    )


@ui_fragments_router.get("/ui/peers/table", response_class=HTMLResponse)
async def ui_peers_table(
    request: Request,
    status: str = "all",
    hide_removed: int = 1,
    page: int = 1,
    page_size: int = 10,
):
    valid_statuses = {"all"} | {s.value for s in ProvisioningStatus}
    if status not in valid_statuses:
        status = "all"

    hide_removed_enabled = bool(hide_removed)

    if page < 1:
        page = 1
    if page_size < 1:
        page_size = 10

    async with AsyncSessionLocal() as db:
        base_stmt = select(Peer)
        if status != "all":
            base_stmt = base_stmt.where(Peer.provisioning_status == ProvisioningStatus(status))
        if hide_removed_enabled and status != "removed":
            base_stmt = base_stmt.where(Peer.provisioning_status != ProvisioningStatus.removed)

        count_stmt = select(func.count()).select_from(base_stmt.subquery())
        total_items = (await db.execute(count_stmt)).scalar_one()

        total_pages = max((total_items + page_size - 1) // page_size, 1)
        if page > total_pages:
            page = total_pages

        stmt = base_stmt.order_by(Peer.id.asc()).offset((page - 1) * page_size).limit(page_size)
        result = await db.execute(stmt)
        peer_rows = result.scalars().all()

    peers = []
    for peer in peer_rows:
        peers.append({
            "id": peer.id,
            "user_id": peer.user_id,
            "vpn_ip": peer.vpn_ip,
            "allowed_ips": peer.allowed_ips,
            "provisioning_status": peer.provisioning_status.value if peer.provisioning_status else "unknown",
            "public_key": peer.public_key,
            "provisioning_error": getattr(peer, "provisioning_error", None),
        })

    filters = {
        "status": status,
        "hide_removed": hide_removed_enabled,
        "page": page,
        "page_size": page_size,
    }

    push_url = "/dashboard?" + urlencode({
        "page_size": page_size,
        "status": status,
        "hide_removed": 1 if hide_removed_enabled else 0,
        "page": page,
    })

    response_headers = {}
    if request.headers.get("HX-Request", "").lower() == "true":
        response_headers["HX-Push-Url"] = push_url

    return templates.TemplateResponse(
        request=request,
        name="peers_table.html",
        context={
            "peers": peers,
            "filters": filters,
            "page": page,
            "page_size": page_size,
            "total_items": total_items,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
        },
        headers=response_headers,
    )


@ui_fragments_router.get("/ui/peers/{peer_id}/details", response_class=HTMLResponse)
async def ui_peer_details(request: Request, peer_id: int):
    async with AsyncSessionLocal() as db:
        peer = await db.get(Peer, peer_id)
        if not peer:
            return HTMLResponse(
                '<div class="px-4 py-3 text-sm text-rose-300">Peer not found.</div>',
                status_code=404,
            )

    allowed = peer.allowed_ips or ""
    cidrs = [item.strip() for item in allowed.split(",") if item.strip()]

    context = {
        "peer": peer,
        "peer_view": {
            "id": peer.id,
            "user_id": peer.user_id,
            "vpn_ip": peer.vpn_ip,
            "public_key": peer.public_key,
            "allowed_ips": allowed,
            "cidrs": cidrs,
            "routes_count": len(cidrs),
            "status": peer.provisioning_status.value if peer.provisioning_status else "unknown",
            "provisioning_error": getattr(peer, "provisioning_error", None),
            "created_at": peer.created_at.strftime("%Y-%m-%d %H:%M") if getattr(peer, "created_at", None) else "—",
            "updated_at": peer.updated_at.strftime("%Y-%m-%d %H:%M") if getattr(peer, "updated_at", None) else "—",
            "revoked_at": (
                peer.revoked_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if getattr(peer, "revoked_at", None)
                else None
            ),
            "purge_at": (
                (
                    (
                        peer.revoked_at
                        if peer.revoked_at.tzinfo is not None
                        else peer.revoked_at.replace(tzinfo=timezone.utc)
                    )
                    .astimezone(timezone.utc)
                    + timedelta(days=30)
                )
                .strftime("%Y-%m-%d %H:%M:%S UTC")
                if getattr(peer, "revoked_at", None)
                else None
            ),
        },
    }

    return templates.TemplateResponse(
        request=request,
        name="peer_details_modal.html",
        context=context,
    )


# Peer regeneration is handled by app.main.ui_peer_regenerate.


@ui_fragments_router.get("/ui/peers/{peer_id}/config")
async def ui_peer_config_download(peer_id: int):
    async with AsyncSessionLocal() as db:
        peer = await db.get(Peer, peer_id)
        if not peer:
            return PlainTextResponse("Peer not found.", status_code=404)

        if peer.provisioning_status in (
            ProvisioningStatus.pending_revoke,
            ProvisioningStatus.removed,
        ):
            return PlainTextResponse(
                "Peer configuration is unavailable because this peer has been revoked.",
                status_code=410,
                headers={"Cache-Control": "no-store"},
            )

    config_text = build_client_config_for_peer(peer)
    filename = f"peer-{peer_id}.conf"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
    }
    return PlainTextResponse(
        content=config_text,
        media_type="text/plain; charset=utf-8",
        headers=headers,
    )


@ui_fragments_router.get("/ui/peers/{peer_id}/qr")
async def ui_peer_config_qr(peer_id: int):
    async with AsyncSessionLocal() as db:
        peer = await db.get(Peer, peer_id)
        if not peer:
            return PlainTextResponse("Peer not found.", status_code=404)

        if peer.provisioning_status in (
            ProvisioningStatus.pending_revoke,
            ProvisioningStatus.removed,
        ):
            return PlainTextResponse(
                "Peer configuration is unavailable because this peer has been revoked.",
                status_code=410,
                headers={"Cache-Control": "no-store"},
            )

    cfg = build_client_config_for_peer(peer)
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_Q,
        box_size=6,
        border=2,
    )
    qr.add_data(cfg)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    return Response(
        content=buf.getvalue(),
        media_type="image/png",
        headers={"Cache-Control": "no-store"},
    )
