import os
from typing import Optional

import httpx
from fastapi import HTTPException


WG_GATEWAY_URL = os.getenv("WG_GATEWAY_URL", "").rstrip("/")
WG_GATEWAY_TOKEN = os.getenv("WG_GATEWAY_TOKEN", "")
WG_GATEWAY_CONNECT_TIMEOUT = float(
    os.getenv("WG_GATEWAY_CONNECT_TIMEOUT", "2.0")
)
WG_GATEWAY_READ_TIMEOUT = float(
    os.getenv("WG_GATEWAY_READ_TIMEOUT", "5.0")
)


def _gateway_timeout() -> httpx.Timeout:
    return httpx.Timeout(
        connect=WG_GATEWAY_CONNECT_TIMEOUT,
        read=WG_GATEWAY_READ_TIMEOUT,
        write=WG_GATEWAY_READ_TIMEOUT,
        pool=WG_GATEWAY_READ_TIMEOUT,
    )


def _gateway_headers() -> dict[str, str]:
    if not WG_GATEWAY_URL:
        raise RuntimeError("WG_GATEWAY_URL must be configured")

    if len(WG_GATEWAY_TOKEN) < 32:
        raise RuntimeError("WG_GATEWAY_TOKEN must be configured securely")

    return {"X-Gateway-Token": WG_GATEWAY_TOKEN}


async def apply_peer_in_gateway(
    public_key: str,
    allowed_ips: str,
    endpoint: Optional[str] = None,
    persistent_keepalive: Optional[int] = None,
) -> None:
    payload = {
        "public_key": public_key,
        "allowed_ips": allowed_ips,
        "endpoint": endpoint,
        "persistent_keepalive": persistent_keepalive,
    }

    try:
        async with httpx.AsyncClient(timeout=_gateway_timeout()) as client:
            response = await client.post(
                f"{WG_GATEWAY_URL}/wg/peers/apply",
                json=payload,
                headers=_gateway_headers(),
            )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"wg-gateway request failed: {exc}",
        ) from exc

    if response.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"wg-gateway error {response.status_code}: {response.text}",
        )


async def remove_peer_in_gateway(public_key: str) -> None:
    try:
        async with httpx.AsyncClient(timeout=_gateway_timeout()) as client:
            response = await client.delete(
                f"{WG_GATEWAY_URL}/wg/peers",
                params={"public_key": public_key},
                headers=_gateway_headers(),
            )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"wg-gateway request failed: {exc}",
        ) from exc

    if response.status_code not in (200, 204):
        raise HTTPException(
            status_code=502,
            detail=(
                f"wg-gateway remove error "
                f"{response.status_code}: {response.text}"
            ),
        )
