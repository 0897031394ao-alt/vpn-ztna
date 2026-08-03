import ipaddress
import re
from datetime import datetime
from pydantic import BaseModel, ConfigDict, model_validator
from app.models.resource import ResourceType


FQDN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)


class ResourceCreate(BaseModel):
    name: str
    description: str | None = None
    resource_type: ResourceType
    address: str
    ports: str | None = None
    protocol: str = "any"

    @model_validator(mode="after")
    def validate_by_type(self) -> "ResourceCreate":
        addr = self.address.strip()
        rtype = self.resource_type
        proto = (self.protocol or "any").strip().lower()
        ports = (self.ports or "").strip()

        allowed_protocols = {"any", "tcp", "udp", "icmp"}
        if proto not in allowed_protocols:
            raise ValueError(
                f"protocol must be one of {sorted(allowed_protocols)}, got '{proto}'"
            )

        if rtype == ResourceType.cidr:
            try:
                ipaddress.ip_network(addr, strict=False)
            except ValueError:
                raise ValueError(
                    f"resource_type=cidr requires a valid CIDR, got '{addr}'"
                )

        elif rtype == ResourceType.host:
            ip_part = addr.split("/")[0]
            try:
                ipaddress.ip_address(ip_part)
            except ValueError:
                raise ValueError(
                    f"resource_type=host requires a valid IP, got '{addr}'"
                )

        elif rtype == ResourceType.service:
            host_part = addr.split(":")[0].split("/")[0]

            is_ip = True
            try:
                ipaddress.ip_address(host_part)
            except ValueError:
                is_ip = False

            is_fqdn = bool(FQDN_RE.fullmatch(host_part))

            if not (is_ip or is_fqdn):
                raise ValueError(
                    f"resource_type=service requires valid IP[:port], got '{addr}'"
                )
            if not ports:
                raise ValueError(
                    "resource_type=service requires 'ports' to be specified"
                )

        if proto == "icmp" and ports:
            raise ValueError("protocol=icmp must not have ports specified")

        return self


class ResourceUpdate(ResourceCreate):
    pass


class ResourceRead(BaseModel):
    id: int
    name: str
    description: str | None = None
    resource_type: ResourceType
    address: str
    ports: str | None = None
    protocol: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
