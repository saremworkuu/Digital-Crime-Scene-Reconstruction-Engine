
# Detection schema
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.db.models.detection import DetectionSeverity


class DetectionResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    rule_id: str
    rule_name: str
    severity: DetectionSeverity
    description: str
    mitre_technique: str | None
    rule_information: dict[str, Any] | None
    is_false_positive: bool
    detected_at: datetime

    event_ids: list[uuid.UUID] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)
