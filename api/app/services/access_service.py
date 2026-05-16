from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network
from typing import Any

from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.peer import Peer
from app.models.group import Group
from app.models.resource import Resource
from app.models.policy import Policy


@dataclass
class AccessDecision:
    peer_id: int
    resource_id: int
    resource_name: str
    address: str
    port: int | None
    protocol: str | None
    action: str


class AccessService:
    @staticmethod
    async def get_peer_with_groups(db: AsyncSession, peer_id: int) -> Peer | None:
        stmt = (
            select(Peer)
            .options(
                selectinload(Peer.groups)
            )
            .where(Peer.id == peer_id)
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_policies_for_peer(db: AsyncSession, peer: Peer) -> list[Policy]:
        group_ids = [g.id for g in getattr(peer, "groups", [])]

        stmt = (
            select(Policy)
            .options(
                selectinload(Policy.resource),
                selectinload(Policy.group),
            )
            .where(
                or_(
                    Policy.peer_id == peer.id,
                    Policy.group_id.in_(group_ids) if group_ids else False,
                )
            )
        )

        result = await db.execute(stmt)
        return list(result.scalars().unique().all())

    @staticmethod
    def _policy_matches_peer(policy: Policy, peer: Peer) -> bool:
        if policy.peer_id is not None and policy.peer_id == peer.id:
            return True

        peer_group_ids = {g.id for g in getattr(peer, "groups", [])}
        if policy.group_id is not None and policy.group_id in peer_group_ids:
            return True

        return False

    @staticmethod
    def _resource_payload(resource: Resource, action: str, peer_id: int) -> AccessDecision:
        return AccessDecision(
            peer_id=peer_id,
            resource_id=resource.id,
            resource_name=resource.name,
            address=resource.address,
            port=getattr(resource, "port", None),
            protocol=getattr(resource, "protocol", None),
            action=action,
        )

    @classmethod
    async def calculate_access_for_peer(cls, db: AsyncSession, peer_id: int) -> dict[str, Any]:
        peer = await cls.get_peer_with_groups(db, peer_id)
        if not peer:
            return {
                "peer_id": peer_id,
                "allowed": [],
                "denied": [],
                "error": "peer_not_found",
            }

        policies = await cls.get_policies_for_peer(db, peer)

        allowed: list[AccessDecision] = []
        denied: list[AccessDecision] = []

        for policy in policies:
            if not cls._policy_matches_peer(policy, peer):
                continue

            if policy.resource_id is None:
                continue

            resource = await db.get(Resource, policy.resource_id)
            if resource is None:
                continue

            action = getattr(policy, "action", "allow")

            item = cls._resource_payload(resource, action, peer.id)
            if action == "allow":
                allowed.append(item)
            else:
                denied.append(item)

        return {
            "peer_id": peer.id,
            "peer_name": getattr(peer, "name", None),
            "allowed": [item.__dict__ for item in allowed],
            "denied": [item.__dict__ for item in denied],
        }

    @classmethod
    async def build_allowed_ips_for_peer(cls, db: AsyncSession, peer_id: int) -> list[str]:
        access = await cls.calculate_access_for_peer(db, peer_id)

        allowed_networks: list[str] = []
        for item in access["allowed"]:
            address = item["address"]
            try:
                net = ip_network(address, strict=False)
                allowed_networks.append(str(net))
            except ValueError:
                continue

        return sorted(set(allowed_networks))
