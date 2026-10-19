# Detection model

# Detection model
import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
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
        default=uuid.uuid4,
    )

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id"),
        nullable=False,
    )

    rule_id: Mapped[str] = mapped_column(
        String,
        nullable=False,
        default="repeated_failed_logins",
        server_default=text("'legacy'"),
    )

    rule_name: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    severity: Mapped[DetectionSeverity] = mapped_column(
        Enum(
            DetectionSeverity,
            name="detection_severity",
            values_callable=lambda enum_class: [
                item.value for item in enum_class
            ],
        ),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    mitre_technique: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    rule_information: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    is_false_positive: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
