from datetime import datetime
from enum import Enum
from typing import Optional

import base64
from pydantic import BaseModel, ConfigDict, field_validator


class ProvisioningStatus(str, Enum):
    pending = "pending"
    provisioned = "provisioned"
    error = "error"
    removed = "removed"
    pending_revoke = "pending_revoke"


class PeerBase(BaseModel):
    user_id: int
    public_key: str

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, v: str) -> str:
        try:
            decoded = base64.b64decode(v, validate=True)
        except Exception:
            raise ValueError("public_key must be valid base64-encoded WireGuard key")

        if len(decoded) != 32:
            raise ValueError("public_key must decode to 32 bytes for WireGuard")

        return v


class PeerCreate(PeerBase):
    pass


class PeerUpdate(BaseModel):
    public_key: Optional[str] = None

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            decoded = base64.b64decode(v, validate=True)
        except Exception:
            raise ValueError("public_key must be valid base64-encoded WireGuard key")

        if len(decoded) != 32:
            raise ValueError("public_key must decode to 32 bytes for WireGuard")

        return v


class PeerRead(BaseModel):
    id: int
    user_id: int
    public_key: str
    vpn_ip: str
    allowed_ips: str
    provisioning_status: ProvisioningStatus
    provisioning_error: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PeerStatsRead(BaseModel):
    pending: int
    provisioned: int
    error: int
    pending_revoke: int
    removed: int
    total: int


class PeerConfigInterface(BaseModel):
    PrivateKey: str
    Address: str
    DNS: Optional[str] = None


class PeerConfigPeer(BaseModel):
    PublicKey: str
    Endpoint: str
    AllowedIPs: str
    PersistentKeepalive: Optional[str] = None


class PeerEnrollResponse(BaseModel):
    peer_id: int
    user_id: int
    config_ini: str
    interface: PeerConfigInterface
    peer: PeerConfigPeer
