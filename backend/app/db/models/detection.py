# Detection model
import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class DetectionSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id"),
        nullable=False
    )

    rule_name: Mapped[str] = mapped_column(
        String,
        nullable=False
    )


    severity: Mapped[DetectionSeverity] = mapped_column(
        Enum(
            DetectionSeverity,
            name="detection_severity",
            values_callable=lambda enum_class: [e.value for e in enum_class]
        ),
        nullable=False
    )


    description: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )