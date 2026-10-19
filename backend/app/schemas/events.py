
# Event schemas
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, field_serializer


class EventResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    evidence_id: uuid.UUID
    timestamp: datetime
    event_type: str
    source: str
    details: dict[str, Any]

    model_config = ConfigDict(from_attributes=True)

    @field_serializer("timestamp")
    def serialize_timestamp(self, value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        value = value.astimezone(timezone.utc)
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class PaginatedEventsResponse(BaseModel):
    items: list[EventResponse]
    total: int
    limit: int
    offset: int
