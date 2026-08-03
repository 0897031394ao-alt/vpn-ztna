import asyncio
from typing import List

from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.peer import Peer, ProvisioningStatus
from app.services.peer_service import provision_peer_by_id, revoke_peer_by_id


EMPTY_LOG_EVERY = 12


async def process_pending_once() -> int:
    """
    Один проход: найти pending peers и попытаться их провизионить.
    Возвращает количество обработанных peers.
    """
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Peer.id)
            .where(Peer.provisioning_status == ProvisioningStatus.pending)
            .order_by(Peer.id)
        )
        peer_ids: List[int] = list(result.scalars().all())

    if not peer_ids:
        return 0

    print(f"Found {len(peer_ids)} pending peer(s): {peer_ids}")

    processed = 0
    for peer_id in peer_ids:
        try:
            async with AsyncSessionLocal() as db:
                peer = await provision_peer_by_id(db, peer_id)
                current_status = (
                    peer.provisioning_status.value
                    if hasattr(peer.provisioning_status, "value")
                    else str(peer.provisioning_status)
                )
                print(
                    f"[OK] peer_id={peer.id} user_id={peer.user_id} "
                    f"to_status={current_status} allowed_ips={peer.allowed_ips}"
                )
                processed += 1
        except Exception as e:
            print(f"[ERROR] peer_id={peer_id} error={e}")

    return processed


async def process_pending_revoke_once() -> int:
    """
    Один проход: найти pending_revoke peers и попытаться их отозвать из wg-gateway.
    Возвращает количество обработанных peers.
    """
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Peer.id)
            .where(Peer.provisioning_status == ProvisioningStatus.pending_revoke)
            .order_by(Peer.id)
        )
        peer_ids: List[int] = list(result.scalars().all())

    if not peer_ids:
        return 0

    print(f"Found {len(peer_ids)} pending_revoke peer(s): {peer_ids}")

    processed = 0
    for peer_id in peer_ids:
        try:
            async with AsyncSessionLocal() as db:
                peer = await revoke_peer_by_id(db, peer_id)
                current_status = (
                    peer.provisioning_status.value
                    if hasattr(peer.provisioning_status, "value")
                    else str(peer.provisioning_status)
                )
                print(
                    f"[OK] revoked peer_id={peer.id} user_id={peer.user_id} "
                    f"to_status={current_status}"
                )
                processed += 1
        except Exception as e:
            print(f"[ERROR] revoke peer_id={peer_id} error={e}")

    return processed


async def run_forever(interval_seconds: int = 5) -> None:
    """
    Бесконечный цикл: раз в interval_seconds секунд проверять pending peers.
    """
    print(
        f"Starting provision worker loop, interval={interval_seconds}s, "
        f"statuses=['pending', 'pending_revoke']"
    )
    empty_cycles = 0

    while True:
        try:
            processed_provision = await process_pending_once()
            processed_revoke = await process_pending_revoke_once()
            processed = processed_provision + processed_revoke

            if processed == 0:
                empty_cycles += 1
                if empty_cycles % EMPTY_LOG_EVERY == 0:
                    print(
                        f"No pending/pending_revoke peers found "
                        f"(empty_cycles={empty_cycles}, interval={interval_seconds}s)"
                    )
            else:
                empty_cycles = 0
        except Exception as e:
            print(f"[FATAL] unhandled error in worker loop: {e}")

        await asyncio.sleep(interval_seconds)


def main() -> None:
    asyncio.run(run_forever())


if __name__ == "__main__":
    main()
