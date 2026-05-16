from app.core.config import settings
from app.models.peer import Peer


def build_client_config_for_peer(peer: Peer) -> str:
    lines: list[str] = []

    # Клиентский интерфейс
    lines.append("[Interface]")
    lines.append("# PrivateKey = <insert your client private key here>")
    lines.append(f"Address = {peer.vpn_ip}/32")
    if settings.WG_CLIENT_DNS:
        lines.append(f"DNS = {settings.WG_CLIENT_DNS}")
    lines.append("")

    # Серверный peer
    lines.append("[Peer]")
    lines.append(f"PublicKey = {settings.WG_SERVER_PUBLIC_KEY}")
    lines.append(f"Endpoint = {settings.WG_SERVER_ENDPOINT}")
    lines.append(f"AllowedIPs = {peer.allowed_ips}")
    lines.append("PersistentKeepalive = 25")

    return "\n".join(lines) + "\n"
