from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.group import Group, user_group
from app.models.peer import Peer
from app.models.policy import Policy
from app.models.resource import Resource
from app.models.user import User
from app.services.policy_engine import (
    calculate_allowed_ips_for_user,
    resource_to_network,
)


async def _get_user_group_ids(db: AsyncSession, user_id: int) -> list[int]:
    result = await db.execute(
        select(user_group.c.group_id).where(user_group.c.user_id == user_id)
    )
    return list(result.scalars().all())


def _scope_label(policy: Policy, user: User, group_ids: list[int]) -> str:
    if policy.user_id is not None and policy.user_id == user.id:
        return f"user:{user.username}"
    if policy.group_id is not None and policy.group_id in group_ids:
        return f"group:{policy.group_id}"
    return "global"


def _policy_applies(
    policy: Policy,
    user_id: int,
    group_ids: list[int],
) -> bool:
    if policy.user_id is not None:
        return policy.user_id == user_id
    if policy.group_id is not None:
        return policy.group_id in group_ids
    return True


async def explain_user_access(
    db: AsyncSession,
    user_id: int,
) -> dict[str, Any]:
    user_result = await db.execute(
        select(User).where(User.id == user_id, User.is_active == True)  # noqa: E712
    )
    user = user_result.scalar_one_or_none()
    if not user:
        return {"user": None, "rows": [], "effective_networks": []}

    group_ids = await _get_user_group_ids(db, user_id)

    resources = list(
        (
            await db.execute(
                select(Resource)
                .where(Resource.is_active == True)  # noqa: E712
                .order_by(Resource.id.asc())
            )
        ).scalars().all()
    )

    all_policies = list(
        (
            await db.execute(
                select(Policy)
                .where(Policy.is_active == True)  # noqa: E712
                .order_by(Policy.priority.asc(), Policy.id.asc())
            )
        ).scalars().all()
    )

    rows = []
    for resource in resources:
        matched = []
        for policy in all_policies:
            if policy.resource_id != resource.id:
                continue
            if not _policy_applies(policy, user.id, group_ids):
                continue
            matched.append(
                {
                    "id": policy.id,
                    "name": policy.name,
                    "effect": (
                        policy.effect.value
                        if hasattr(policy.effect, "value")
                        else str(policy.effect)
                    ),
                    "priority": policy.priority,
                    "subject": _scope_label(policy, user, group_ids),
                    "conditions": policy.conditions,
                }
            )

        matched.sort(key=lambda x: (x["priority"], x["id"]))

        decision = "deny"
        reason = "implicit deny"
        winning_policy = None

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
                "resource_type": (
                    resource.resource_type.value
                    if hasattr(resource.resource_type, "value")
                    else str(resource.resource_type)
                ),
                "address": resource.address,
                "protocol": resource.protocol,
                "decision": decision,
                "reason": reason,
                "matched_policies": matched,
                "winning_policy": winning_policy,
            }
        )

    effective_networks = await calculate_allowed_ips_for_user(db, user_id)

    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "group_ids": group_ids,
        },
        "rows": rows,
        "effective_networks": effective_networks,
    }


async def explain_peer_access(
    db: AsyncSession,
    peer_id: int,
) -> dict[str, Any]:
    peer_result = await db.execute(
        select(Peer).where(Peer.id == peer_id)
    )
    peer = peer_result.scalar_one_or_none()

    if not peer:
        return {"peer": None, "user": None, "rows": [], "effective_networks": []}

    user_result = await explain_user_access(db=db, user_id=peer.user_id)

    stored = set(
        ip.strip()
        for ip in (peer.allowed_ips or "").split(",")
        if ip.strip()
    )
    computed = set(user_result.get("effective_networks", []))

    return {
        "peer": {
            "id": peer.id,
            "public_key": peer.public_key,
            "vpn_ip": peer.vpn_ip,
            "allowed_ips": peer.allowed_ips,
            "provisioning_status": (
                peer.provisioning_status.value
                if hasattr(peer.provisioning_status, "value")
                else str(peer.provisioning_status)
            ),
            "user_id": peer.user_id,
        },
        "user": user_result["user"],
        "rows": user_result["rows"],
        "effective_networks": user_result["effective_networks"],
        "diff": {
            "stored_only": sorted(stored - computed),
            "computed_only": sorted(computed - stored),
            "in_sync": stored == computed,
        },
    }


async def explain_user_resource_access(
    db: AsyncSession,
    user_id: int,
    resource_id: int,
) -> dict[str, Any]:
    user_result = await db.execute(
        select(User).where(User.id == user_id, User.is_active == True)  # noqa: E712
    )
    resource_result = await db.execute(
        select(Resource).where(
            Resource.id == resource_id,
            Resource.is_active == True,  # noqa: E712
        )
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

    group_ids = await _get_user_group_ids(db, user.id)

    group_names: list[str] = []
    if group_ids:
        groups = list(
            (
                await db.execute(
                    select(Group)
                    .where(Group.id.in_(group_ids))
                    .order_by(Group.name.asc())
                )
            ).scalars().all()
        )
        group_names = [g.name for g in groups]

    policies = list(
        (
            await db.execute(
                select(Policy)
                .where(
                    Policy.is_active == True,  # noqa: E712
                    Policy.resource_id == resource.id,
                )
                .order_by(Policy.priority.asc(), Policy.id.asc())
            )
        ).scalars().all()
    )

    matched_policies = []
    for policy in policies:
        if not _policy_applies(policy, user.id, group_ids):
            continue
        matched_policies.append(
            {
                "id": policy.id,
                "name": policy.name,
                "effect": (
                    policy.effect.value
                    if hasattr(policy.effect, "value")
                    else str(policy.effect)
                ),
                "priority": policy.priority,
                "subject": _scope_label(policy, user, group_ids),
                "conditions": policy.conditions,
            }
        )

    matched_policies.sort(key=lambda x: (x["priority"], x["id"]))

    decision = "deny"
    reason = "implicit deny"
    winning_policy = None

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

    net = resource_to_network(resource)

    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
        },
        "resource": {
            "id": resource.id,
            "name": resource.name,
            "resource_type": (
                resource.resource_type.value
                if hasattr(resource.resource_type, "value")
                else str(resource.resource_type)
            ),
            "address": resource.address,
            "protocol": resource.protocol,
            "ports": resource.ports,
            "network": str(net) if net else None,
        },
        "decision": decision,
        "reason": reason,
        "matched_policies": matched_policies,
        "winning_policy": winning_policy,
        "group_names": group_names,
    }
