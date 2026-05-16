from __future__ import annotations

from typing import List, Set, Tuple
import ipaddress
from dataclasses import dataclass
from sqlalchemy import and_, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from app.models.peer import Peer, ProvisioningStatus
from app.models.policy import Policy, PolicyEffect
from app.models.resource import Resource, ResourceType


def _resource_to_cidr(resource: Resource) -> str | None:
    """
    Приводит Resource к CIDR для WireGuard AllowedIPs.

    - ResourceType.cidr    -> address (ожидается CIDR, например 10.0.0.0/24)
    - ResourceType.host    -> address + '/32' (если это IPv4 без маски)
    - ResourceType.service -> ip часть address + '/32' (порт отбрасываем)

    Если формат некорректный — возвращает None.
    """
    addr = resource.address.strip()

    if resource.resource_type == ResourceType.cidr:
        # Считаем, что address уже CIDR (валидация на уровне схем/админки)
        return addr

    if resource.resource_type == ResourceType.host:
        # Если уже CIDR — оставляем как есть, если просто IP — добавляем /32
        if "/" in addr:
            return addr
        return f"{addr}/32"

    if resource.resource_type == ResourceType.service:
        # Ожидаем формат "ip:port" или "ip:port1,port2"
        ip_part = addr.split(":", 1)[0]
        if "/" in ip_part:
            return ip_part
        return f"{ip_part}/32"

    return None


def aggregate_cidrs(cidr_list: List[str]) -> List[str]:
    """
    Принимает список CIDR-строк, возвращает агрегированный список.
    Гарантия: множество IP-адресов на выходе === множеству на входе.
    Работает только с IPv4.
    """
    networks: list[ipaddress.IPv4Network] = []

    for cidr in cidr_list:
        cidr = cidr.strip()
        if not cidr:
            continue
        net = ipaddress.ip_network(cidr, strict=True)
        if isinstance(net, ipaddress.IPv6Network):
            raise ValueError(f"IPv6 not supported yet: {cidr}")
        networks.append(net)

    if not networks:
        return []

    # Убираем дубликаты и сортируем
    networks = sorted(set(networks), key=lambda n: (int(n.network_address), n.prefixlen))

    # 1. Схлопываем пересекающиеся и вложенные сети
    current = list(ipaddress.collapse_addresses(networks))

    # 2. Пытаемся объединять соседние сети одинакового префикса,
    # пока что-то сливается
    merged = True
    while merged:
        merged = False
        new_list: list[ipaddress.IPv4Network] = []
        i = 0
        n = len(current)

        while i < n:
            if i + 1 < n:
                a = current[i]
                b = current[i + 1]

                if a.prefixlen == b.prefixlen:
                    try:
                        supernet = a.supernet(prefixlen_diff=1)
                    except ValueError:
                        supernet = None

                    if supernet:
                        children = list(supernet.subnets(prefixlen_diff=1))
                        if len(children) == 2 and children[0] == a and children[1] == b:
                            new_list.append(supernet)
                            i += 2
                            merged = True
                            continue

            new_list.append(current[i])
            i += 1

        current = sorted(set(new_list), key=lambda n: (int(n.network_address), n.prefixlen))

    return [str(net) for net in current]


def _policy_scope(policy: Policy) -> str:
    """
    Определяет scope политики по заполненности user_id / group_id:
    - global: user_id is None, group_id is None
    - group: user_id is None, group_id not None
    - user: user_id not None, group_id is None
    - hybrid: user_id not None, group_id not None
    """
    if policy.user_id is None and policy.group_id is None:
        return "global"
    if policy.user_id is None and policy.group_id is not None:
        return "group"
    if policy.user_id is not None and policy.group_id is None:
        return "user"
    return "hybrid"


_SCOPE_RANK = {
    "global": 0,
    "group": 1,
    "user": 2,
    "hybrid": 3,
}


@dataclass
class PolicyStep:
    policy_id: int
    name: str
    scope: str
    effect: str
    resource_cidr: str | None
    before: List[str]
    after: List[str]


async def _get_applicable_policies_for_peer(
    db: AsyncSession,
    peer: Peer,
) -> List[Policy]:
    """
    Возвращает список активных политик, применимых к peer'у по user_id и группам.

    Поддерживаются:
    - global:   user_id IS NULL, group_id IS NULL      (ко всем пользователям)
    - group:    user_id IS NULL, group_id IN (...)     (по группам)
    - user:     user_id == peer.user_id, group_id IS NULL
    - hybrid:   user_id == peer.user_id, group_id IN (...)  (особые случаи)

    Далее они сортируются по priority ASC, затем по scope_rank, затем id ASC.
    """
    if peer.user_id is None:
        return []

    # 1. Получаем группы пользователя
    group_ids: List[int] = []
    group_rows = await db.execute(
        text(
        """
        SELECT ug.group_id
        FROM user_group ug
        WHERE ug.user_id = :user_id
        """
        ),
        {"user_id": peer.user_id},
    )
    group_ids = [row[0] for row in group_rows.all()]

    # 2. Собираем все подходящие политики
    #    Условие: активные, и хотя бы одно из:
    #    - global: user_id IS NULL AND group_id IS NULL
    #    - group:  user_id IS NULL AND group_id IN (:group_ids)
    #    - user:   user_id = :user_id AND group_id IS NULL
    #    - hybrid: user_id = :user_id AND group_id IN (:group_ids)
    where_clauses = [
        Policy.is_active == True,  # noqa: E712
    ]

    # global-политики
    # user_id IS NULL AND group_id IS NULL
    global_filter = (Policy.user_id.is_(None) & Policy.group_id.is_(None))

    # user-политики
    user_filter = (Policy.user_id == peer.user_id)

    # group/hybrid-политики
    if group_ids:
        group_filter = Policy.group_id.in_(group_ids)
    else:
        group_filter = Policy.id == -1  # заведомо ложное, если групп нет

    # Объединяем: хотя бы одно из условий global/user/group/hybrid
    where_clauses.append(
        (global_filter) | (user_filter) | (group_filter)
    )

    result = await db.execute(
        select(Policy)
        .options(selectinload(Policy.resource))
        .where(*where_clauses)
        .order_by(Policy.priority.asc(), Policy.id.asc())
    )

    policies: List[Policy] = list(result.scalars().all())

    # 3. Сортируем по priority ASC, затем по scope_rank, затем по id ASC
    def sort_key(p: Policy) -> Tuple[int, int, int]:
        scope = _policy_scope(p)
        rank = _SCOPE_RANK.get(scope, 99)
        return (p.priority, rank, p.id)

    policies.sort(key=sort_key)
    return policies


async def _simulate_policies_for_peer(
    db: AsyncSession,
    peer: Peer,
) -> tuple[List[str], List[PolicyStep]]:
    """
    Прогоняет все применимые политики для peer'а и возвращает:
    - итоговый список CIDR перед агрегацией (строки)
    - список шагов применения политик (PolicyStep) в порядке выполнения
    """
    cidrs: List[str] = []

    # Собственный IP всегда стартовый
    if peer.vpn_ip:
        cidrs.append(peer.vpn_ip)

    if peer.user_id is None:
        # Если нет user_id — только свой IP или дефолт
        return (cidrs if cidrs else ["0.0.0.0/0"], [])

    policies = await _get_applicable_policies_for_peer(db, peer)

    allowed: Set[str] = set(cidrs)
    steps: List[PolicyStep] = []

    for policy in policies:
        # Явно загружаем ресурс через async-сессию, чтобы избежать MissingGreenlet
        if policy.resource_id is None:
            continue

        resource = await db.get(Resource, policy.resource_id)
        if not resource or not resource.is_active:
            continue

        cidr = _resource_to_cidr(resource)
        if not cidr:
            continue

        before = sorted(allowed)
        scope = _policy_scope(policy)

        if policy.effect == PolicyEffect.allow:
            allowed.add(cidr)
        elif policy.effect == PolicyEffect.deny:
            if cidr in allowed:
                allowed.remove(cidr)

        after = sorted(allowed)

        steps.append(
            PolicyStep(
                policy_id=policy.id,
                name=policy.name,
                scope=scope,
                effect=policy.effect.value if hasattr(policy.effect, "value") else str(policy.effect),
                resource_cidr=cidr,
                before=before,
                after=after,
            )
        )

    if not allowed:
        return (["0.0.0.0/0"], steps)

    return (sorted(allowed), steps)


async def calculate_allowed_ips(db: AsyncSession, user_id: int) -> str:
    stmt = (
        select(Policy)
        .where(Policy.user_id == user_id)
        .options(selectinload(Policy.resource))  # ВАЖНО
    )
    result = await db.execute(stmt)
    policies = result.scalars().all()

    cidrs: set[str] = set()
    for policy in policies:
        res = policy.resource
        if not res or not res.is_active:
            continue
        if res.resource_cidr:
            cidrs.add(res.resource_cidr.strip())

    return ", ".join(sorted(cidrs)) if cidrs else ""


async def get_policies_for_group(db: AsyncSession, group_id: int) -> List[Policy]:
    """
    Временно оставляем для обратной совместимости, но сейчас
    engine работает только с user-based политиками.
    """
    result = await db.execute(
        select(Policy).where(
            Policy.group_id == group_id,
        )
    )
    return result.scalars().all()


async def recalculate_all_peers_in_group(db: AsyncSession, group_id: int) -> List[Peer]:
    """
    Формально пересчитывает allowed_ips для всех provisioned-пиров группы,
    но сама логика calculate_allowed_ips опирается только на user_id.

    WG-гейтвей не трогает — только БД.
    """
    result = await db.execute(
        select(Peer).where(
            Peer.provisioning_status == ProvisioningStatus.provisioned,
            # Если в будущем добавим group_id в Peer, сюда вернём фильтр по группе
            # Peer.group_id == group_id,
        )
    )
    peers = result.scalars().all()

    for peer in peers:
        peer.allowed_ips = await calculate_allowed_ips(db, peer)

    await db.commit()
    return peers
