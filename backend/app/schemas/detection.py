# Detection schema
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, List
from pydantic import BaseModel, ConfigDict, Field, field_serializer

from app.db.models.detection import DetectionSeverity


class DetectionResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    rule_id: str
    rule_name: str
    severity: DetectionSeverity
    description: str
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = "Execution"
    rule_information: Optional[dict[str, Any]] = None
    is_false_positive: bool = False
    false_positive: bool = False
    false_positive_reason: Optional[str] = None
    detected_at: datetime
    timestamp: Optional[str] = None

    event_ids: List[uuid.UUID] = Field(default_factory=list)
    matched_event_ids: List[str] = Field(default_factory=list)
    entities_involved: Optional[dict[str, List[str]]] = Field(
        default_factory=lambda: {"hosts": [], "users": [], "ips": []}
    )

    model_config = ConfigDict(from_attributes=True)

    @field_serializer("detected_at")
    def serialize_detected_at(self, value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class FalsePositiveRequest(BaseModel):
    false_positive: bool = True
    reason: Optional[str] = None


class DetectionRuleResponse(BaseModel):
    id: str
    name: str
    severity: str
    mitre_technique: str
    mitre_tactic: str
    description: str
    author: Optional[str] = "DCSRE Core"
    status: Optional[str] = "active"
    tags: List[str] = Field(default_factory=list)
    yaml_content: Optional[str] = None
