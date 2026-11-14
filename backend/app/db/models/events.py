import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Event(Base):
    __tablename__ = "events"

    __table_args__ = (
        UniqueConstraint(
            "case_id",
           "fingerprint",
            name="uq_events_case_fingerprint",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id"),
        nullable=False,
    )

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence.id"),
        nullable=False,
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    event_type: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    source: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    details: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
    )

    fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
