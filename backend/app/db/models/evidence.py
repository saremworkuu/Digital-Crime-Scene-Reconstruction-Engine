# Evidence model
import uuid
import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

class ParsingStatus(str,enum.Enum):
    PENDING="pending"
    PARSED="parsed"
    FAILED="failed"

class Evidence(Base):
    __tablename__ = "evidence"

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
    uploaded_by:Mapped[uuid.UUID]=mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False
    ) 

    filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    description:Mapped[str]=mapped_column(
        Text,
        default="",
        nullable=True
    )
    file_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )
    file_path:Mapped[str]=mapped_column(
        String(1024),
        nullable=False
    )
    sha256_hash:Mapped[str]=mapped_column(
        String(64),
        nullable=False
    )

    file_size: Mapped[int] = mapped_column(
        Integer,
        nullable=False
    )

    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    parsing_status:Mapped[ParsingStatus]=mapped_column(
        Enum(
            ParsingStatus,
            name="evidence_parsing_status",
            values_callable=lambda cls:[item.value for item in cls],
        ),
        default=ParsingStatus.PENDING,
        nullable=False,
    )

    parser_used:Mapped[str|None]=mapped_column(
        String(100),
        nullable=True,
    )
    parsing_error:Mapped[str|None]=mapped_column(
        Text,
        nullable=True
    )
    expected_sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True
    )
    verified: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True
    )