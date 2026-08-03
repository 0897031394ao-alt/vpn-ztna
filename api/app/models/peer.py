import enum
from datetime import datetime, timezone

from sqlalchemy import String, Text, Integer, ForeignKey, Enum as SAEnum, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ProvisioningStatus(str, enum.Enum):
    pending = "pending"
    provisioned = "provisioned"
    error = "error"
    pending_revoke = "pending_revoke"
    removed = "removed"


class Peer(Base):
    __tablename__ = "peers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # единый public_key
    public_key: Mapped[str] = mapped_column(String(88), unique=True, nullable=False, index=True)

    # приватный ключ клиента для выдачи актуального .conf / QR
    client_private_key: Mapped[str | None] = mapped_column(String(88), nullable=True)

    # VPN IP клиента
    vpn_ip: Mapped[str] = mapped_column(String(18), unique=True, nullable=False, index=True)

    # allowed IPs, которые получит peer
    allowed_ips: Mapped[str] = mapped_column(Text, nullable=False)

    provisioning_status: Mapped[ProvisioningStatus] = mapped_column(
        SAEnum(
            ProvisioningStatus,
            name="provisioningstatus",
            values_callable=lambda enum_cls: [item.value for item in enum_cls],
            validate_strings=True,
        ),
        default=ProvisioningStatus.pending,
        nullable=False,
        server_default=ProvisioningStatus.pending.value,
        index=True,
    )

    provisioning_error: Mapped[str | None] = mapped_column(String(512), nullable=True)

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    user: Mapped["User"] = relationship("User", back_populates="peers")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    @property
    def is_active(self) -> bool:
        return self.provisioning_status == ProvisioningStatus.provisioned

    @property
    def is_revoked(self) -> bool:
        return self.provisioning_status in {
            ProvisioningStatus.pending_revoke,
            ProvisioningStatus.removed,
        }

    @property
    def can_be_revoked(self) -> bool:
        return self.provisioning_status in {
            ProvisioningStatus.pending,
            ProvisioningStatus.provisioned,
            ProvisioningStatus.error,
        }

    def mark_pending_revoke(self) -> None:
        if self.provisioning_status == ProvisioningStatus.removed:
            return
        self.provisioning_status = ProvisioningStatus.pending_revoke
        self.provisioning_error = None

    def mark_removed(self) -> None:
        self.provisioning_status = ProvisioningStatus.removed
        self.revoked_at = datetime.now(timezone.utc)
        self.provisioning_error = None

    def mark_revoke_error(self, message: str) -> None:
        self.provisioning_status = ProvisioningStatus.error
        self.provisioning_error = (message or "peer revoke failed")[:512]
