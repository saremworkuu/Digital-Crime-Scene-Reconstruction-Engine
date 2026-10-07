# User model

import enum
import uuid

from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, String

from sqlalchemy.dialects.postgresql import UUID 
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

class UserRole(str, enum.Enum):
    ADMIN="admin"
    ANALYST="analyst"

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID]=mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    username: Mapped[str]=mapped_column(
        String,
        unique=True,
        nullable=False
    )

    email: Mapped[str]=mapped_column(
        String,
        unique=True,
        nullable=False
    )

    hashed_password:Mapped[str]=mapped_column(
        String,
        nullable=False
    )

    role: Mapped[UserRole] = mapped_column(
    Enum(
        UserRole,
        name="user_role",
        values_callable=lambda enum_class: [e.value for e in enum_class]
    ),
    nullable=False,
    default=UserRole.ANALYST
)

    created_at: Mapped[datetime]=mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(datetime.UTC),
        nullable=False
    )

    updated_at: Mapped[datetime]=mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(datetime.UTC),
        onupdate=lambda: datetime.now(datetime.UTC),
        nullable=False
    )