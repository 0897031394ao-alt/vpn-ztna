import enum
from datetime import datetime

from sqlalchemy import String, Boolean, Text, Integer, DateTime, func, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ResourceType(str, enum.Enum):
    cidr = "cidr"
    host = "host"
    service = "service"


class Resource(Base):
    __tablename__ = "resources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)

    description: Mapped[str | None] = mapped_column(String(512), nullable=True)
    resource_type: Mapped[ResourceType] = mapped_column(
        SAEnum(ResourceType, name="resourcetype"),
        nullable=False,
    )

    resource_cidr: Mapped[str | None] = mapped_column(Text, nullable=True)

    address: Mapped[str] = mapped_column(String(256), nullable=False)
    ports: Mapped[str | None] = mapped_column(String(256), nullable=True)
    protocol: Mapped[str] = mapped_column(String(16), default="any", nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    policies: Mapped[list["Policy"]] = relationship("Policy", back_populates="resource")
