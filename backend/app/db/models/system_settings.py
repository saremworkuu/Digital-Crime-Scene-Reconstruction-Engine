from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class SystemSettings(Base):
    __tablename__ = "system_settings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default="default")
    time_zone: Mapped[str] = mapped_column(String(100), default="UTC+03:00 (Addis Ababa / EAT)", nullable=False)
    org_name: Mapped[str] = mapped_column(String(255), default="Ethiopian Cyber Defense & DFIR Command", nullable=False)
    retention_days: Mapped[int] = mapped_column(Integer, default=365, nullable=False)
    min_password_length: Mapped[int] = mapped_column(Integer, default=12, nullable=False)
    two_factor_enforced: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    failed_login_lockout_limit: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
