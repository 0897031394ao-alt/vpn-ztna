import ipaddress
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.peer import Peer

SUBNET = ipaddress.IPv4Network("100.64.0.0/10")
GATEWAY_IP = "100.64.0.1"

async def allocate_vpn_ip(db: AsyncSession) -> str:
    result = await db.execute(select(Peer.vpn_ip))
    used = {row[0] for row in result.fetchall()}

    for host in SUBNET.hosts():
        ip = str(host)
        if ip == GATEWAY_IP:
            continue
        if ip not in used:
            return ip
    raise RuntimeError("VPN subnet exhausted")
