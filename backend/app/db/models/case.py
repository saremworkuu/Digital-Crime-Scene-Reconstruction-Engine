# Case model

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

class CaseStatus(str,enum.Enum):
    OPEN="open"
    CLOSED="closed"

class Case(Base):
    __tablename__="cases"

    id: Mapped[uuid.UUID]=mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    name:Mapped[str]=mapped_column(
        String,
        nullable=False
    )

    description:Mapped[str|None]=mapped_column(
        Text,
        nullable=True
    )

    status: Mapped[CaseStatus] = mapped_column(
    Enum(
        CaseStatus,
        name="case_status",
        values_callable=lambda enum_class: [e.value for e in enum_class]
    ),
    nullable=False,
    default=CaseStatus.OPEN
)

    created_by:Mapped[uuid.UUID]=mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )