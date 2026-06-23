from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi import Response
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin, get_current_user, get_current_admin_or_self
from app.core.deps import get_db
from app.models.peer import Peer, ProvisioningStatus
from app.models.user import User
from app.schemas.peer import (
    PeerCreate,
    PeerRead,
    PeerStatsRead,
    PeerUpdate,
    PeerEnrollResponse,
)
from app.services.config_service import build_client_config_for_peer
from app.services.policy_service import calculate_allowed_ips, _simulate_policies_for_peer
from app.services.peer_service import (
    register_peer,
    recalculate_peer_by_id,
    provision_peer_by_id,
    provision_peer_in_gateway,
    remove_peer_by_id,
    validate_wg_public_key,
    register_peer_for_user,
)
from app.services.audit_service import log_event

router = APIRouter(prefix="/peers", tags=["peers"])


@router.post("/", response_model=PeerRead)
async def register_peer_endpoint(
    payload: PeerCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    if not validate_wg_public_key(payload.public_key):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid WireGuard public key",
        )
    return await register_peer(db, payload)


@router.post("/users/{user_id}/enroll-peer", response_model=PeerEnrollResponse)
async def enroll_peer_for_user(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin_or_self),
):
    if not current_user.is_admin and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions to enroll peer for another user",
        )

    peer = await register_peer_for_user(db, user_id)
    peer = await recalculate_peer_by_id(db, peer.id)
    peer = await provision_peer_by_id(db, peer.id)

    await log_event(
        db,
        action="peer.enroll",
        current_user=current_user,
        peer=peer,
        details={
            "user_id": peer.user_id,
            "peer_id": peer.id,
            "vpn_ip": peer.vpn_ip,
            "provisioning_status": peer.provisioning_status.value
            if hasattr(peer.provisioning_status, "value")
            else str(peer.provisioning_status),
        },
        request=request,
    )

    await db.commit()
    await db.refresh(peer)

    config_text = build_client_config_for_peer(peer)

    interface_block: dict[str, str] = {}
    peer_block: dict[str, str] = {}
    current_section: Optional[str] = None

    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("[") and line.endswith("]"):
            if line == "[Interface]":
                current_section = "interface"
            elif line == "[Peer]":
                current_section = "peer"
            else:
                current_section = None
            continue

        if current_section is None:
            continue

        if "=" not in line:
            continue

        key, value = [part.strip() for part in line.split("=", 1)]

        if key.startswith("#"):
            normalized_key = key.lstrip("#").strip()
            if normalized_key == "PrivateKey":
                key = "PrivateKey"
            else:
                continue

        if current_section == "interface":
            interface_block[key] = value
        elif current_section == "peer":
            peer_block[key] = value

    if "PrivateKey" not in interface_block:
        interface_block["PrivateKey"] = "<insert-your-wireguard-private-key>"

    return PeerEnrollResponse(
        peer_id=peer.id,
        user_id=peer.user_id,
        config_ini=config_text,
        interface=interface_block,
        peer=peer_block,
    )


@router.post("/my/enroll", response_model=PeerEnrollResponse)
async def enroll_my_peer(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Self-service peer enrollment for текущего аутентифицированного пользователя.
    Повторяет полный флоу как у admin /users/{user_id}/enroll-peer.
    """
    # 1) Сгенерировать peer
    peer = await register_peer_for_user(db, current_user.id)

    # 2) Пересчитать allowed_ips по политикам
    peer = await recalculate_peer_by_id(db, peer.id)

    # 3) Отправить peer в wg-gateway
    peer = await provision_peer_by_id(db, peer.id)

    # 4) Записать событие
    await log_event(
        db,
        action="peer.enroll_self",
        current_user=current_user,
        peer=peer,
        details={
            "user_id": peer.user_id,
            "peer_id": peer.id,
            "vpn_ip": peer.vpn_ip,
            "provisioning_status": (
                peer.provisioning_status.value
                if hasattr(peer.provisioning_status, "value")
                else str(peer.provisioning_status)
            ),
        },
        request=request,
    )

    await db.commit()
    await db.refresh(peer)

    # 5) Собрать INI-конфиг и разбить на блоки, как в admin-эндпоинте
    config_text = build_client_config_for_peer(peer)

    interface_block: dict[str, str] = {}
    peer_block: dict[str, str] = {}
    current_section: Optional[str] = None

    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("[") and line.endswith("]"):
            if line == "[Interface]":
                current_section = "interface"
            elif line == "[Peer]":
                current_section = "peer"
            else:
                current_section = None
            continue

        if current_section is None:
            continue

        if "=" not in line:
            continue

        key, value = [part.strip() for part in line.split("=", 1)]

        if key.startswith("#"):
            normalized_key = key.lstrip("#").strip()
            if normalized_key == "PrivateKey":
                key = "PrivateKey"
            else:
                continue

        if current_section == "interface":
            interface_block[key] = value
        elif current_section == "peer":
            peer_block[key] = value

    if "PrivateKey" not in interface_block:
        interface_block["PrivateKey"] = "<insert-your-wireguard-private-key>"

    return PeerEnrollResponse(
        peer_id=peer.id,
        user_id=peer.user_id,
        config_ini=config_text,
        interface=interface_block,
        peer=peer_block,
    )


# Админский список всех peers
@router.get("/", response_model=List[PeerRead])
async def list_peers_endpoint(
    filter_status: Optional[ProvisioningStatus] = Query(default=None, alias="status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    stmt = select(Peer)

    if filter_status is not None:
        stmt = stmt.where(Peer.provisioning_status == filter_status)

    stmt = stmt.order_by(Peer.id)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/my", response_model=List[PeerRead])
async def list_my_peers_endpoint(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = (
        select(Peer)
        .where(Peer.user_id == current_user.id)
        .order_by(Peer.id)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/stats", response_model=PeerStatsRead)
async def peers_stats_endpoint(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(
        select(Peer.provisioning_status, func.count(Peer.id))
        .group_by(Peer.provisioning_status)
    )
    rows = result.all()

    stats = {
        "pending": 0,
        "provisioned": 0,
        "error": 0,
        "removed": 0,
        "total": 0,
    }

    for status, count in rows:
        key = status.value if hasattr(status, "value") else str(status)
        if key in stats:
            stats[key] = count
            stats["total"] += count

    return PeerStatsRead(**stats)


@router.get("/my/config")
async def get_my_config(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Вернуть WireGuard-конфиг для текущего пользователя.
    Формат: text/plain, как готовый .conf.
    """

    stmt = (
        select(Peer)
        .where(
            Peer.user_id == current_user.id,
            Peer.provisioning_status == ProvisioningStatus.provisioned,
        )
        .order_by(Peer.id.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    peer = result.scalars().first()

    if peer is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No peer found for current user",
        )

    await log_event(
        db,
        action="peer.get_config",
        current_user=current_user,
        peer=peer,
        details={
            "user_id": peer.user_id,
            "peer_id": peer.id,
            "vpn_ip": peer.vpn_ip,
        },
        request=request,
    )

    await db.commit()

    config_text = build_client_config_for_peer(peer)

    return Response(
        content=config_text,
        media_type="text/plain",
        headers={
            "Content-Disposition": 'attachment; filename="wg0.conf"',
        },
    )


@router.get("/my/policy-explain")
async def explain_my_policies(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Вернуть объяснение, почему у текущего пользователя такие AllowedIPs.
    Берём последний provisioned peer этого пользователя.
    """

    stmt = (
        select(Peer)
        .where(
            Peer.user_id == current_user.id,
            Peer.provisioning_status == ProvisioningStatus.provisioned,
        )
        .order_by(Peer.id.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    peer = result.scalars().first()

    if peer is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No provisioned peer found for current user",
        )

    final_cidrs, steps = await _simulate_policies_for_peer(db, peer)

    allowed_steps = [s for s in steps if str(s.effect).lower() == "allow"]
    denied_steps = [s for s in steps if str(s.effect).lower() == "deny"]

    has_full_internet_access = "0.0.0.0/0" in final_cidrs
    effective_access_mode = "full_tunnel" if has_full_internet_access else "split_tunnel"

    await log_event(
        db,
        action="peer.my_policy_explain",
        current_user=current_user,
        peer=peer,
        details={
            "user_id": peer.user_id,
            "peer_id": peer.id,
            "vpn_ip": peer.vpn_ip,
            "final_cidrs_count": len(final_cidrs),
            "steps_count": len(steps),
        },
        request=request,
    )

    await db.commit()

    return {
        "peer_id": peer.id,
        "user_id": peer.user_id,
        "vpn_ip": peer.vpn_ip,
        "summary": {
            "effective_access_mode": effective_access_mode,
            "has_full_internet_access": has_full_internet_access,
            "allowed_count": len(final_cidrs),
            "allowed_policies_count": len(allowed_steps),
            "denied_policies_count": len(denied_steps),
        },
        "final_cidrs_before_aggregation": final_cidrs,
        "steps": [
            {
                "policy_id": s.policy_id,
                "name": s.name,
                "scope": s.scope,
                "effect": s.effect,
                "resource_cidr": s.resource_cidr,
                "before": s.before,
                "after": s.after,
            }
            for s in steps
        ],
    }


# Админский пересчёт AllowedIPs и статуса peer
@router.post("/{peer_id}/recalculate", response_model=PeerRead)
async def recalculate_peer_endpoint(
    peer_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    peer = await recalculate_peer_by_id(db, peer_id)

    await log_event(
        db,
        action="peer.recalculate_manual",
        current_user=current_user,
        peer=peer,
        details={
            "user_id": peer.user_id,
            "peer_id": peer.id,
            "vpn_ip": peer.vpn_ip,
            "provisioning_status": (
                peer.provisioning_status.value
                if hasattr(peer.provisioning_status, "value")
                else str(peer.provisioning_status)
            ),
        },
        request=request,
    )

    # Гарантируем, что и peer, и audit_log попадут в БД
    await db.commit()
    await db.refresh(peer)

    return peer


@router.patch("/{peer_id}", response_model=PeerRead)
async def update_peer_endpoint(
    peer_id: int,
    payload: PeerUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(select(Peer).where(Peer.id == peer_id))
    peer = result.scalar_one_or_none()
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found")

    update_data = payload.model_dump(exclude_unset=True)

    if not update_data:
        return peer

    if "public_key" in update_data:
        peer.public_key = update_data["public_key"]

    peer.provisioning_status = ProvisioningStatus.pending
    peer.provisioning_error = None

    await db.commit()
    await db.refresh(peer)

    return await recalculate_peer_by_id(db, peer_id)


@router.post("/{peer_id}/retry", response_model=PeerRead)
async def retry_peer_endpoint(
    peer_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(select(Peer).where(Peer.id == peer_id))
    peer = result.scalar_one_or_none()
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found")

    if peer.provisioning_status != ProvisioningStatus.error:
        current_status = (
            peer.provisioning_status.value
            if hasattr(peer.provisioning_status, "value")
            else str(peer.provisioning_status)
        )
        raise HTTPException(
            status_code=409,
            detail=f"Retry is allowed only for peers in 'error' status, current status: '{current_status}'",
        )

    peer.provisioning_status = ProvisioningStatus.pending
    peer.provisioning_error = None

    await db.commit()
    await db.refresh(peer)

    return peer


@router.delete("/{peer_id}", response_model=PeerRead, status_code=202)
async def remove_peer_endpoint(
    peer_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    peer = await remove_peer_by_id(db, peer_id)

    await log_event(
        db,
        action="peer.remove",
        current_user=current_user,
        peer=peer,
        details={
            "user_id": peer.user_id,
            "peer_id": peer.id,
            "provisioning_status": peer.provisioning_status.value
            if hasattr(peer.provisioning_status, "value")
            else str(peer.provisioning_status),
        },
        request=request,
    )

    await db.commit()
    await db.refresh(peer)

    return peer


# Админский ручной provision peer
@router.post("/{peer_id}/provision", response_model=PeerRead)
async def provision_peer_endpoint(
    peer_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    return await provision_peer_by_id(db, peer_id)


@router.post("/debug/wg/provision-peer/{peer_id}")
async def debug_provision_peer_endpoint(
    peer_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(select(Peer).where(Peer.id == peer_id))
    peer = result.scalar_one_or_none()
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found")

    await provision_peer_in_gateway(peer)

    return {
        "status": "sent_to_gateway",
        "peer_id": peer.id,
        "user_id": peer.user_id,
        "public_key": peer.public_key,
        "allowed_ips": peer.allowed_ips,
    }


@router.get("/{peer_id}/config")
async def get_peer_config_endpoint(
    peer_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(select(Peer).where(Peer.id == peer_id))
    peer = result.scalar_one_or_none()
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found")

    config_text = build_client_config_for_peer(peer)
    return Response(
        content=config_text,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="peer-{peer.id}.conf"'
        },
    )


@router.get("/{peer_id}/policy-explain")
async def explain_peer_policies(
    peer_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    peer = await db.get(Peer, peer_id)
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found")

    final_cidrs, steps = await _simulate_policies_for_peer(db, peer)

    allowed_steps = [s for s in steps if str(s.effect).lower() == "allow"]
    denied_steps = [s for s in steps if str(s.effect).lower() == "deny"]

    has_full_internet_access = "0.0.0.0/0" in final_cidrs
    effective_access_mode = "full_tunnel" if has_full_internet_access else "split_tunnel"

    await log_event(
        db,
        action="peer.policy_explain",
        current_user=current_user,
        peer=peer,
        details={
            "user_id": peer.user_id,
            "peer_id": peer.id,
            "vpn_ip": peer.vpn_ip,
            "final_cidrs_count": len(final_cidrs),
            "steps_count": len(steps),
        },
        request=request,
    )

    await db.commit()

    return {
        "peer_id": peer.id,
        "user_id": peer.user_id,
        "vpn_ip": peer.vpn_ip,
        "summary": {
            "effective_access_mode": effective_access_mode,
            "has_full_internet_access": has_full_internet_access,
            "allowed_count": len(final_cidrs),
            "allowed_policies_count": len(allowed_steps),
            "denied_policies_count": len(denied_steps),
        },
        "final_cidrs_before_aggregation": final_cidrs,
        "steps": [
            {
                "policy_id": s.policy_id,
                "name": s.name,
                "scope": s.scope,
                "effect": s.effect,
                "resource_cidr": s.resource_cidr,
                "before": s.before,
                "after": s.after,
            }
            for s in steps
        ],
    }


