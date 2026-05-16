import enum
from datetime import datetime
from sqlalchemy import String, Text, Integer, ForeignKey, Enum as SAEnum, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class ProvisioningStatus(str, enum.Enum):
    pending     = "pending"
    provisioned = "provisioned"
    error       = "error"
    removed     = "removed"


class Peer(Base):
    __tablename__ = "peers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # единый public_key
    public_key: Mapped[str] = mapped_column(String(88), unique=True, nullable=False)

    # если ip больше не нужен, оставляем только vpn_ip
    vpn_ip: Mapped[str] = mapped_column(String(18), unique=True, nullable=False)

    # единое allowed_ips
    allowed_ips: Mapped[str] = mapped_column(Text, nullable=False)

    provisioning_status: Mapped[ProvisioningStatus] = mapped_column(
        SAEnum(ProvisioningStatus),
        default=ProvisioningStatus.pending,
        nullable=False,
    )
    provisioning_error: Mapped[str | None] = mapped_column(String(512), nullable=True)

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    user: Mapped["User"] = relationship("User", back_populates="peers")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
