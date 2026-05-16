from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.peer import Peer
from app.models.user import User
from app.models.policy import Policy
from app.models.resource import Resource
from app.api.deps import get_current_admin


router = APIRouter(prefix="/debug", tags=["debug"])


@router.get("/orm", summary="Debug async ORM behaviour")
async def debug_orm(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    result: dict = {
        "peer_loaded": False,
        "peer_user_loaded": False,
        "policies_loaded": False,
        "resource_loaded": False,
        "after_commit_access_ok": False,
    }

    peer = (
        await db.execute(
            select(Peer)
            .options(selectinload(Peer.user))
            .order_by(Peer.id)
            .limit(1)
        )
    ).scalars().first()

    if not peer:
        return {
            "error": "no_peers",
            "details": "В таблице peers нет записей",
        }

    result["peer_loaded"] = True

    try:
        _ = peer.user
        result["peer_user_loaded"] = True
    except Exception as e:
        result["peer_user_error"] = repr(e)

    policy = (
        await db.execute(
            select(Policy)
            .options(selectinload(Policy.resource))
            .order_by(Policy.id)
            .limit(1)
        )
    ).scalars().first()

    if policy:
        result["policies_loaded"] = True
        try:
            _ = policy.resource
            result["resource_loaded"] = True
        except Exception as e:
            result["resource_error"] = repr(e)

    try:
        await db.commit()
        _ = peer.id
        _ = peer.user_id
        result["after_commit_access_ok"] = True
    except Exception as e:
        result["after_commit_error"] = repr(e)

    return result


@router.get("/peer/{peer_id}", summary="Debug peer policies")
async def debug_peer(
    peer_id: int,
    deny_only: bool = Query(default=False),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    peer = (
        await db.execute(
            select(Peer)
            .where(Peer.id == peer_id)
            .options(selectinload(Peer.user))
        )
    ).scalars().first()

    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found")

    policies = (
        await db.execute(
            select(Policy)
            .where(Policy.user_id == peer.user_id)
            .options(selectinload(Policy.resource))
            .order_by(Policy.priority.desc(), Policy.id)
        )
    ).scalars().all()

    if deny_only:
        policies = [p for p in policies if (p.effect or "").lower() == "deny"]

    return {
        "peer_id": peer.id,
        "user_id": peer.user_id,
        "username": peer.user.username if peer.user else None,
        "vpn_ip": getattr(peer, "vpn_ip", None),
        "allowed_ips": getattr(peer, "allowed_ips", None),
        "deny_only_filter": deny_only,
        "policies_count": len(policies),
        "policies": [
            {
                "policy_id": p.id,
                "effect": p.effect,
                "priority": p.priority,
                "resource_id": p.resource_id,
                "resource_name": p.resource.name if p.resource else None,
                "resource_cidr": p.resource.resource_cidr if p.resource else None,
                "resource_is_active": p.resource.is_active if p.resource else None,
            }
            for p in policies
        ],
    }


@router.get("/access/{peer_id}", summary="Debug access matrix")
async def debug_access(
    peer_id: int,
    deny_only: bool = Query(default=False),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    peer = (
        await db.execute(
            select(Peer)
            .where(Peer.id == peer_id)
            .options(selectinload(Peer.user))
        )
    ).scalars().first()

    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found")

    resources = (
        await db.execute(
            select(Resource)
            .where(Resource.is_active == True)
            .order_by(Resource.id)
        )
    ).scalars().all()

    policies = (
        await db.execute(
            select(Policy)
            .where(Policy.user_id == peer.user_id)
            .options(selectinload(Policy.resource))
            .order_by(Policy.priority.desc(), Policy.id)
        )
    ).scalars().all()

    by_resource: dict[int, list[Policy]] = {}
    for p in policies:
        if p.resource_id is not None:
            by_resource.setdefault(p.resource_id, []).append(p)

    rows = []
    for resource in resources:
        matched = by_resource.get(resource.id, [])
        effects = [(p.effect or "").lower() for p in matched]

        if "deny" in effects:
            decision = "deny"
        elif "allow" in effects or "базовая" in effects:
            decision = "allow"
        else:
            decision = "no_policy"

        if deny_only and decision != "deny":
            continue

        rows.append(
            {
                "resource_id": resource.id,
                "resource_name": resource.name,
                "resource_cidr": resource.resource_cidr,
                "decision": decision,
                "matched_policies": [
                    {
                        "policy_id": p.id,
                        "effect": p.effect,
                        "priority": p.priority,
                    }
                    for p in matched
                ],
            }
        )

    return {
        "peer_id": peer.id,
        "user_id": peer.user_id,
        "username": peer.user.username if peer.user else None,
        "deny_only_filter": deny_only,
        "resources_total": len(resources),
        "rows_shown": len(rows),
        "access_matrix": rows,
    }

