import os
from typing import Optional

import httpx
from fastapi import HTTPException

WG_GATEWAY_URL = os.getenv("WG_GATEWAY_URL", "http://localhost:51821")


async def apply_peer_in_gateway(
    public_key: str,
    allowed_ips: str,
    endpoint: Optional[str] = None,
    persistent_keepalive: Optional[int] = None,
) -> None:
    """
    Отправляет peer в сервис wg-gateway.

    :raises HTTPException: если wg-gateway вернул ошибку или недоступен.
    """
    payload = {
        "public_key": public_key,
        "allowed_ips": allowed_ips,
        "endpoint": endpoint,
        "persistent_keepalive": persistent_keepalive,
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(f"{WG_GATEWAY_URL}/wg/peers/apply", json=payload)
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"wg-gateway request failed: {e}")

    if resp.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"wg-gateway error {resp.status_code}: {resp.text}",
        )


async def remove_peer_in_gateway(public_key: str) -> None:
    """
    Удаляет peer из wg-gateway по public_key.

    :raises HTTPException: если wg-gateway вернул ошибку или недоступен.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.delete(
                f"{WG_GATEWAY_URL}/wg/peers",
                params={"public_key": public_key},
            )
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"wg-gateway request failed: {e}")

    if resp.status_code not in (200, 204):
        raise HTTPException(
            status_code=502,
            detail=f"wg-gateway remove error {resp.status_code}: {resp.text}",
        )
