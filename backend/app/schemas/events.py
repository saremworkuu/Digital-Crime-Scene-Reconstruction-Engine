# Event schemas
import re
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
        if isinstance(data, dict):
            d = dict(data)
        elif hasattr(data, "details"):
            d = {
                "id": getattr(data, "id", None),
                "case_id": getattr(data, "case_id", None),
                "evidence_id": getattr(data, "evidence_id", None),
                "timestamp": getattr(data, "timestamp", None),
                "event_type": getattr(data, "event_type", "event"),
                "source": getattr(data, "source", "unknown"),
                "details": getattr(data, "details", {}) or {},
            }
        else:
            return data

        details = d.get("details") or {}
        if not isinstance(details, dict):
            details = {}
        src = d.get("source") or details.get("source") or "unknown"
        ev_type = d.get("event_type") or details.get("event_type") or "event"

        # Host extraction
        host = details.get("host") or details.get("Computer") or details.get("WorkstationName") or details.get("hostname")
        if not host:
            raw_msg = str(details.get("raw_message") or details.get("raw") or "")
            syslog_match = re.match(r"^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+([a-zA-Z0-9_\-\.]+)", raw_msg)
            if syslog_match:
                host = syslog_match.group(1)
            else:
                host = "SRV-FILE-01"
        # User extraction
        user = details.get("user") or details.get("username") or details.get("TargetUserName") or details.get("SubjectUserName") or "unknown"
        # Action extraction
        action = (
            details.get("action")
            or details.get("message")
            or details.get("Message")
            or details.get("raw_message")
            or details.get("description")
            or ev_type
            or "System Event"
        )
        # IP extraction
        src_ip = details.get("source_ip") or details.get("src_ip") or details.get("IpAddress") or details.get("ip")
        dst_ip = details.get("destination_ip") or details.get("dst_ip")
        # Port
        src_port = details.get("source_port") or details.get("src_port")
        dst_port = details.get("destination_port") or details.get("dst_port")

        is_suspicious = any(
            w in str(ev_type).lower() or w in str(action).lower()
            for w in ["fail", "error", "attack", "malware", "shell", "sudo", "privilege", "brute", "inject", "drop", "unauthorized"]
        )
        severity = details.get("severity") or ("high" if is_suspicious else "medium")
        raw = details.get("raw") or details.get("raw_message") or details.get("original_log") or str(details)

        d["source_type"] = src
        d["host"] = host
        d["user"] = user
        d["action"] = action
        d["outcome"] = details.get("outcome", "failure" if "fail" in str(ev_type).lower() else "success")
        d["severity"] = severity
        d["raw"] = raw
        d["src_ip"] = src_ip
        d["dst_ip"] = dst_ip
        d["src_port"] = int(src_port) if src_port is not None and str(src_port).isdigit() else None
        d["dst_port"] = int(dst_port) if dst_port is not None and str(dst_port).isdigit() else None
        d["protocol"] = details.get("protocol") or ("TCP" if src_port else None)
        d["process"] = details.get("process") or details.get("NewProcessName")
        d["mitre_technique"] = details.get("mitre_technique") or ("T1110.001" if "fail" in str(ev_type).lower() or "brute" in str(ev_type).lower() else None)
        d["mitre_tactic"] = details.get("mitre_tactic") or ("Credential Access" if "fail" in str(ev_type).lower() or "brute" in str(ev_type).lower() else None)
        d["is_attack_path"] = bool(details.get("is_attack_path", False) or is_suspicious)
        d["attack_phase"] = details.get("attack_phase") or ("Credential Access" if "fail" in str(ev_type).lower() else None)
        return d


class PaginatedEventsResponse(BaseModel):
    items: List[EventResponse]
    total: int
    limit: int
    offset: int
