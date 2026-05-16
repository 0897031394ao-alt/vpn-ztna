from typing import List
import base64
import subprocess
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.peer import Peer, ProvisioningStatus
from app.models.user import User
from app.schemas.peer import PeerCreate
from app.services.ip_allocator import allocate_vpn_ip
from app.services.policy_engine import calculate_allowed_ips_for_user
from app.services.wg_client import apply_peer_in_gateway, remove_peer_in_gateway
from app.services.audit_service import log_event


def build_allowed_ips(vpn_ip: str, policy_allowed_ips: list[str]) -> str:
    """
    Собирает итоговый список AllowedIPs для peer:
    - всегда включает собственный vpn_ip как /32;
    - добавляет все маршруты из policy;
    - убирает дубликаты и сортирует для детерминированности.
    """
    allowed_ips_list = [f"{vpn_ip}/32", *policy_allowed_ips]
    return ",".join(sorted(set(allowed_ips_list)))


async def recalculate_peer_allowed_ips(db: AsyncSession, peer: Peer) -> Peer:
    """
    Пересчитывает allowed_ips для конкретного peer на основе актуальных политик пользователя.
    Ставит peer в статус pending и очищает provisioning_error.
    """
    policy_allowed_ips = await calculate_allowed_ips_for_user(db, peer.user_id)

    # Если активных политик нет — оставляем только собственный vpn_ip/32.
    # Это безопаснее, чем кидать 403 при любом изменении политик.
    if not policy_allowed_ips:
        peer.allowed_ips = f"{peer.vpn_ip}/32"
    else:
        peer.allowed_ips = build_allowed_ips(peer.vpn_ip, policy_allowed_ips)

    peer.provisioning_status = ProvisioningStatus.pending
    peer.provisioning_error = None

    await db.commit()
    await db.refresh(peer)
    return peer


async def recalculate_peers_for_user(db: AsyncSession, user_id: int) -> List[Peer]:
    """
    Пересчитывает allowed_ips для всех peers указанного пользователя.
    Используется при изменении политик или ресурсов.
    """
    result = await db.execute(
        select(Peer).where(Peer.user_id == user_id)
    )
    peers = result.scalars().all()

    if not peers:
        return []

    for peer in peers:
        policy_allowed_ips = await calculate_allowed_ips_for_user(db, peer.user_id)

        if not policy_allowed_ips:
            peer.allowed_ips = f"{peer.vpn_ip}/32"
        else:
            peer.allowed_ips = build_allowed_ips(peer.vpn_ip, policy_allowed_ips)

        peer.provisioning_status = ProvisioningStatus.pending
        peer.provisioning_error = None

    # Один общий commit для всех peers пользователя
    await db.commit()

    for peer in peers:
        await db.refresh(peer)
    for peer in peers:
        await log_event(
            db,
            action="peer_recalculated",
            current_user=None,
            peer=peer,
            resource=None,
            details={"new_allowed_ips": peer.allowed_ips, "bulk": True},
        )
    await db.commit()

    return peers


async def register_peer(db: AsyncSession, payload: PeerCreate) -> Peer:
    """
    Регистрирует peer:
    - если peer с таким public_key уже существует — пересчитывает его allowed_ips и возвращает;
    - иначе создаёт нового peer, выделяет vpn_ip и считает allowed_ips по политикам.
    """
    existing_result = await db.execute(
        select(Peer).where(Peer.public_key == payload.public_key)
    )
    existing = existing_result.scalar_one_or_none()
    if existing:
        # Для повторного вызова с тем же ключом делаем мягкий idempotent:
        # просто актуализируем allowed_ips по текущим политикам.
        return await recalculate_peer_allowed_ips(db, existing)

    user_result = await db.execute(
        select(User).where(User.id == payload.user_id)
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    policy_allowed_ips = await calculate_allowed_ips_for_user(db, payload.user_id)
    if not policy_allowed_ips:
        # При первой регистрации без политик явно запрещаем, чтобы не
        # создавать "немые" peers; это можно осознанно ослабить позже.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No active access policies for this user",
        )

    vpn_ip = await allocate_vpn_ip(db)
    allowed_ips = build_allowed_ips(vpn_ip, policy_allowed_ips)

    peer = Peer(
        user_id=payload.user_id,
        public_key=payload.public_key,
        vpn_ip=vpn_ip,
        allowed_ips=allowed_ips,
        provisioning_status=ProvisioningStatus.pending,
    )

    db.add(peer)
    await db.commit()
    await db.refresh(peer)

    # Пишем событие peer_created без привязки к пользователю (user_id видно в peer)
    await log_event(
        db,
        action="peer_created",
        current_user=None,
        peer=peer,
        resource=None,
        details={"user_id": peer.user_id, "public_key": peer.public_key},
    )
    await db.commit()

    return peer


async def register_peer_for_user(db: AsyncSession, user_id: int) -> Peer:
    """
    Регистрирует нового peer для заданного пользователя:
    - генерирует WireGuard ключи;
    - создаёт PeerCreate с user_id + public_key;
    - использует уже существующую логику register_peer().
    """
    # Проверяем, что пользователь существует
    user_result = await db.execute(select(User).where(User.id == user_id))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    private_key, public_key = generate_wireguard_keypair()

    # Собираем payload как если бы его прислал клиент
    payload = PeerCreate(user_id=user.id, public_key=public_key)

    peer = await register_peer(db, payload)

    # ВАЖНО: private_key нигде не сохраняем в БД,
    # но можем вернуть его наверх через временное поле,
    # чтобы потом собрать конфиг.
    peer._private_key = private_key  # временное поле в рантайме

    return peer


async def list_peers(db: AsyncSession) -> List[Peer]:
    result = await db.execute(select(Peer))
    return result.scalars().all()


async def get_peer_or_404(db: AsyncSession, peer_id: int) -> Peer:
    result = await db.execute(select(Peer).where(Peer.id == peer_id))
    peer = result.scalar_one_or_none()
    if not peer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Peer not found",
        )
    return peer


async def get_peer_with_user(db: AsyncSession, peer_id: int) -> Peer | None:
    stmt = (
        select(Peer)
        .where(Peer.id == peer_id)
        .options(selectinload(Peer.user))
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def recalculate_peer_by_id(db: AsyncSession, peer_id: int) -> Peer:
    peer = await get_peer_or_404(db, peer_id)

    old_allowed_ips = peer.allowed_ips
    peer = await recalculate_peer_allowed_ips(db, peer)

    await log_event(
        db,
        action="peer_recalculated",
        current_user=None,
        peer=peer,
        resource=None,
        details={
            "old_allowed_ips": old_allowed_ips,
            "new_allowed_ips": peer.allowed_ips,
        },
    )
    await db.commit()

    return peer


async def provision_peer_in_gateway(peer: Peer) -> None:
    """
    Отправляет peer в wg-gateway через HTTP.
    Предполагается, что peer.allowed_ips уже актуален.
    """
    await apply_peer_in_gateway(
        public_key=peer.public_key,
        allowed_ips=peer.allowed_ips,
        endpoint=None,
        persistent_keepalive=None,
    )


async def provision_peer_by_id(db: AsyncSession, peer_id: int) -> Peer:
    peer = await get_peer_or_404(db, peer_id)

    try:
        await provision_peer_in_gateway(peer)
    except HTTPException as e:
        peer.provisioning_status = ProvisioningStatus.error
        peer.provisioning_error = str(e.detail)
        await db.commit()
        await db.refresh(peer)

        await log_event(
            db,
            action="peer_provision_failed",
            current_user=None,
            peer=peer,
            resource=None,
            details={"error": peer.provisioning_error},
        )
        await db.commit()

        raise

    peer.provisioning_status = ProvisioningStatus.provisioned
    peer.provisioning_error = None
    await db.commit()
    await db.refresh(peer)

    await log_event(
        db,
        action="peer_provisioned",
        current_user=None,
        peer=peer,
        resource=None,
        details={"status": "success"},
    )
    await db.commit()

    return peer


async def remove_peer_by_id(db: AsyncSession, peer_id: int) -> Peer:
    """
    Логическое удаление peer'а:
    - достаёт peer по id;
    - удаляет peer из WireGuard через wg-gateway;
    - помечает peer статусом removed и очищает provisioning_error.
    """
    peer = await get_peer_or_404(db, peer_id)

    # Здесь считаем, что wg-gateway сам корректно обрабатывает ситуацию,
    # когда peer уже отсутствует в конфигурации.
    await remove_peer_in_gateway(
        public_key=peer.public_key,
    )

    peer.provisioning_status = ProvisioningStatus.removed
    peer.provisioning_error = None

    await db.commit()
    await db.refresh(peer)
    await log_event(
        db,
        action="peer_removed",
        current_user=None,
        peer=peer,
        resource=None,
        details={"public_key": peer.public_key},
    )
    await db.commit()

    return peer


def validate_wg_public_key(key: str) -> bool:
    try:
        decoded = base64.b64decode(key, validate=True)
        return len(decoded) == 32
    except Exception:
        return False


def generate_wireguard_keypair() -> tuple[str, str]:
    """
    Генерирует пару ключей WireGuard (private, public) в base64-строках.
    Требует наличия wg в PATH (на хосте/в контейнере).
    """
    # private key
    private_key = subprocess.check_output(["wg", "genkey"]).strip()
    # public key
    public_key = subprocess.check_output(["wg", "pubkey"], input=private_key).strip()

    return private_key.decode(), public_key.decode()
