import enum
from datetime import datetime
from sqlalchemy import String, Integer, ForeignKey, DateTime, func, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class PolicyEffect(str, enum.Enum):
    allow = "allow"
    deny  = "deny"


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Субъект: кому дана политика — group или user (одно из двух, второе NULL)
    group_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=True, index=True
    )
    user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )

    # Объект: к чему применяется
    resource_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("resources.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Разрешить или запретить
    effect: Mapped[PolicyEffect] = mapped_column(
        SAEnum(PolicyEffect), default=PolicyEffect.allow, nullable=False
    )

    # Приоритет: меньше = выше приоритет
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)

    # Контекстные условия: os_name, time_range — JSON-строка
    # Пример: '{"os_name": "Windows", "time_range": "08:00-18:00"}'
    conditions: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    group: Mapped["Group | None"] = relationship("Group", back_populates="policies")
    user: Mapped["User | None"] = relationship("User", back_populates="policies")
    resource: Mapped["Resource"] = relationship("Resource", back_populates="policies")
