# Event schemas
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, List

from pydantic import BaseModel, ConfigDict, field_serializer, model_validator


class EventResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    evidence_id: uuid.UUID
    timestamp: datetime
    event_type: str
    source: str
    details: dict[str, Any]

    # Enriched fields for direct frontend consumption
    source_type: Optional[str] = None
    host: Optional[str] = "host01.local"
    user: Optional[str] = "unknown"
    action: Optional[str] = ""
    outcome: Optional[str] = "unknown"
    severity: Optional[str] = "low"
    raw: Optional[str] = ""
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    process: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    is_attack_path: Optional[bool] = False
    attack_phase: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

    @field_serializer("timestamp")
    def serialize_timestamp(self, value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        value = value.astimezone(timezone.utc)
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    @model_validator(mode="before")
    @classmethod
    def populate_details_fields(cls, data: Any) -> Any:
        # If it's an ORM object or dict, ensure flattened detail fields are populated
        if hasattr(data, "details") and isinstance(data.details, dict):
            details = data.details
            src = getattr(data, "source", None) or details.get("source")
            ev_type = getattr(data, "event_type", None) or details.get("event_type")

            # Host extraction
            host = details.get("host") or details.get("Computer") or details.get("WorkstationName") or details.get("hostname")
            # User extraction
            user = details.get("user") or details.get("username") or details.get("TargetUserName") or details.get("SubjectUserName")
            # Action extraction
            action = details.get("action") or details.get("message") or details.get("Message") or details.get("description") or ev_type or "System Event"
            # IP extraction
            src_ip = details.get("source_ip") or details.get("src_ip") or details.get("IpAddress") or details.get("ip")
            dst_ip = details.get("destination_ip") or details.get("dst_ip")
            # Port
            src_port = details.get("source_port") or details.get("src_port")
            dst_port = details.get("destination_port") or details.get("dst_port")
            # Severity
            severity = details.get("severity") or ("critical" if details.get("is_attack_path") else "low")
            raw = details.get("raw") or details.get("original_log") or str(details)

            # Assign dynamically if dict
            if isinstance(data, dict):
                data.setdefault("source_type", src)
                data.setdefault("host", host or "host01.local")
                data.setdefault("user", user or "unknown")
                data.setdefault("action", action)
                data.setdefault("outcome", details.get("outcome", "success"))
                data.setdefault("severity", severity)
                data.setdefault("raw", raw)
                data.setdefault("src_ip", src_ip)
                data.setdefault("dst_ip", dst_ip)
                data.setdefault("src_port", int(src_port) if src_port is not None and str(src_port).isdigit() else None)
                data.setdefault("dst_port", int(dst_port) if dst_port is not None and str(dst_port).isdigit() else None)
                data.setdefault("protocol", details.get("protocol"))
                data.setdefault("process", details.get("process") or details.get("NewProcessName"))
                data.setdefault("mitre_technique", details.get("mitre_technique"))
                data.setdefault("mitre_tactic", details.get("mitre_tactic"))
                data.setdefault("is_attack_path", bool(details.get("is_attack_path", False)))
                data.setdefault("attack_phase", details.get("attack_phase"))
        return data


class PaginatedEventsResponse(BaseModel):
    items: List[EventResponse]
    total: int
    limit: int
    offset: int
