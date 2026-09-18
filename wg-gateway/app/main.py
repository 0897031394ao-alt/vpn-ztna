import hmac
import os
import subprocess
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel


WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
WG_PORT = int(os.getenv("WG_PORT", "51820"))
WG_ADDRESS = os.getenv("WG_ADDRESS", "100.64.0.1/32")
WG_PRIVATE_KEY_FILE = os.getenv("WG_PRIVATE_KEY_FILE", "/data/server.key")
WG_GATEWAY_TOKEN = os.getenv("WG_GATEWAY_TOKEN", "")

if len(WG_GATEWAY_TOKEN) < 32:
    raise RuntimeError("WG_GATEWAY_TOKEN must be set to a strong secret")


app = FastAPI(
    title="wg-gateway",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


class ApplyPeerRequest(BaseModel):
    public_key: str
    allowed_ips: str
    endpoint: Optional[str] = None
    persistent_keepalive: Optional[int] = None


def require_gateway_token(
    x_gateway_token: str | None = Header(
        default=None,
        alias="X-Gateway-Token",
    ),
) -> None:
    if (
        x_gateway_token is None
        or not hmac.compare_digest(x_gateway_token, WG_GATEWAY_TOKEN)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid gateway token",
        )


def run_cmd(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def ensure_wg_interface() -> None:
    check = run_cmd(["ip", "link", "show", WG_INTERFACE])
    if check.returncode != 0:
        create = run_cmd(
            ["ip", "link", "add", "dev", WG_INTERFACE, "type", "wireguard"]
        )
        if create.returncode != 0:
            raise RuntimeError(
                f"cannot create {WG_INTERFACE}: {create.stderr.strip()}"
            )

    addr_show = run_cmd(["ip", "address", "show", "dev", WG_INTERFACE])
    if WG_ADDRESS.split("/")[0] not in addr_show.stdout:
        addr_add = run_cmd(
            ["ip", "address", "add", WG_ADDRESS, "dev", WG_INTERFACE]
        )
        if addr_add.returncode != 0 and "File exists" not in addr_add.stderr:
            raise RuntimeError(
                f"cannot assign address: {addr_add.stderr.strip()}"
            )

    if not os.path.exists(WG_PRIVATE_KEY_FILE):
        raise RuntimeError(
            f"private key file not found: {WG_PRIVATE_KEY_FILE}"
        )

    wg_set = run_cmd(
        [
            "wg",
            "set",
            WG_INTERFACE,
            "private-key",
            WG_PRIVATE_KEY_FILE,
            "listen-port",
            str(WG_PORT),
        ]
    )
    if wg_set.returncode != 0:
        raise RuntimeError(
            f"cannot configure {WG_INTERFACE}: {wg_set.stderr.strip()}"
        )

    link_up = run_cmd(["ip", "link", "set", "up", "dev", WG_INTERFACE])
    if link_up.returncode != 0:
        raise RuntimeError(
            f"cannot bring up {WG_INTERFACE}: {link_up.stderr.strip()}"
        )


@app.on_event("startup")
def startup_event():
    ensure_wg_interface()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/wg/show", dependencies=[Depends(require_gateway_token)])
def wg_show():
    proc = run_cmd(["wg", "show", WG_INTERFACE])
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail=proc.stderr.strip())
    return {"interface": WG_INTERFACE, "output": proc.stdout}


@app.post(
    "/wg/peers/apply",
    dependencies=[Depends(require_gateway_token)],
)
def apply_peer(payload: ApplyPeerRequest):
    cmd = [
        "wg",
        "set",
        WG_INTERFACE,
        "peer",
        payload.public_key,
        "allowed-ips",
        payload.allowed_ips,
    ]

    if payload.endpoint:
        cmd += ["endpoint", payload.endpoint]

    if payload.persistent_keepalive is not None:
        cmd += [
            "persistent-keepalive",
            str(payload.persistent_keepalive),
        ]

    proc = run_cmd(cmd)
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail=proc.stderr.strip())

    return {
        "status": "applied",
        "interface": WG_INTERFACE,
        "public_key": payload.public_key,
        "allowed_ips": payload.allowed_ips,
    }


@app.delete(
    "/wg/peers",
    dependencies=[Depends(require_gateway_token)],
)
def remove_peer(public_key: str):
    cmd = [
        "wg",
        "set",
        WG_INTERFACE,
        "peer",
        public_key,
        "remove",
    ]

    proc = run_cmd(cmd)
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail=proc.stderr.strip())

    return {
        "status": "removed",
        "interface": WG_INTERFACE,
        "public_key": public_key,
    }
