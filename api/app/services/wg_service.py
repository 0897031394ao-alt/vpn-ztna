import os
import subprocess
from typing import Optional


WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")


class WireGuardError(Exception):
    pass


def _run_wg(*args: str) -> str:
    """
    Запускает `wg` с нужными аргументами и возвращает stdout как строку.
    Бросает WireGuardError при ненулевом коде выхода или отсутствии бинарника.
    """
    cmd = ["wg", *args]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise WireGuardError("wg binary not found in PATH")

    if proc.returncode != 0:
        raise WireGuardError(
            f"wg {' '.join(args)} failed with code {proc.returncode}: {proc.stderr.strip()}"
        )
    return proc.stdout


def apply_peer(
    public_key: str,
    allowed_ips: str,
    endpoint: Optional[str] = None,
    persistent_keepalive: Optional[int] = None,
) -> None:
    """
    Добавляет/обновляет peer в WireGuard:
    - public_key — ключ клиента,
    - allowed_ips — строка с CIDR через запятую (как в БД),
    - endpoint (опционально) — host:port,
    - persistent_keepalive (опционально) — секунды.
    """
    args = [WG_INTERFACE, "peer", public_key, "allowed-ips", allowed_ips]

    if endpoint:
        args += ["endpoint", endpoint]

    if persistent_keepalive is not None:
        args += ["persistent-keepalive", str(persistent_keepalive)]

    _run_wg("set", *args)


def remove_peer(public_key: str) -> None:
    """
    Удаляет peer из WireGuard по public_key.
    """
    _run_wg("set", WG_INTERFACE, "peer", public_key, "remove")


def show_interface() -> str:
    """
    Возвращает `wg show` для интерфейса wg0 (для дебага).
    """
    return _run_wg("show", WG_INTERFACE)
