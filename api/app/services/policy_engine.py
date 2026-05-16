from ipaddress import ip_network, ip_address, IPv4Network
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.user import User
from app.models.policy import Policy, PolicyEffect
from app.models.resource import Resource, ResourceType


def resource_to_network(resource: Resource) -> IPv4Network | None:
    if resource.resource_type == ResourceType.cidr:
        try:
            return ip_network(resource.address, strict=False)
        except Exception:
            return None

    if resource.resource_type in {ResourceType.host, ResourceType.service}:
        try:
            return ip_network(f"{ip_address(resource.address)}/32", strict=False)
        except Exception:
            return None

    return None


def subtract_network(base: IPv4Network, denied: IPv4Network) -> list[IPv4Network]:
    if not base.overlaps(denied):
        return [base]

    if denied.supernet_of(base) or denied == base:
        return []

    if denied.subnet_of(base):
        return list(base.address_exclude(denied))

    return [base]


def subtract_many(base: IPv4Network, denied_list: list[IPv4Network]) -> list[IPv4Network]:
    result = [base]

    for denied in denied_list:
        next_result: list[IPv4Network] = []
        for net in result:
            next_result.extend(subtract_network(net, denied))
        result = next_result

    return result


async def calculate_allowed_ips_for_user(
    db: AsyncSession,
    user_id: int,
) -> list[str]:
    user_result = await db.execute(
        select(User)
        .options(selectinload(User.groups))
        .where(User.id == user_id)
    )
    user = user_result.scalar_one_or_none()
    if not user:
        return []

    group_ids = [g.id for g in user.groups]

    policy_result = await db.execute(
        select(Policy)
        .options(selectinload(Policy.resource))
        .where(Policy.is_active == True)
        .order_by(Policy.priority.asc(), Policy.id.asc())
    )
    policies = policy_result.scalars().all()

    allow_networks: list[IPv4Network] = []
    deny_networks: list[IPv4Network] = []

    for policy in policies:
        applies = False

        if policy.user_id is not None and policy.user_id == user_id:
            applies = True
        elif policy.group_id is not None and policy.group_id in group_ids:
            applies = True

        if not applies:
            continue

        if policy.resource_id is None:
            continue

        resource = await db.get(Resource, policy.resource_id)
        if not resource or not resource.is_active:
            continue

        network = resource_to_network(resource)
        if not network:
            continue

        if policy.effect == PolicyEffect.allow:
            allow_networks.append(network)
        elif policy.effect == PolicyEffect.deny:
            deny_networks.append(network)

    final_networks: list[IPv4Network] = []

    for allow_net in allow_networks:
        final_networks.extend(subtract_many(allow_net, deny_networks))

    unique_networks = sorted(set(final_networks), key=lambda n: (int(n.network_address), n.prefixlen))
    return [str(net) for net in unique_networks]
