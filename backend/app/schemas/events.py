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
    timestamp_timezone_known: Optional[bool] = None
    event_type: str
    source: str
    details: dict[str, Any]

    # Enriched canonical fields for frontend and analysis consumption (Stage 2)
    source_type: Optional[str] = None
    host: Optional[str] = "unknown_host"
    host_inferred: Optional[bool] = False
    source_file: Optional[str] = None
    source_record_id: Optional[Any] = None
    event_id: Optional[Any] = None
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
    bytes: Optional[int] = None
    process: Optional[str] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    service_name: Optional[str] = None
    target_file: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    is_attack_path: Optional[bool] = False
    attack_phase: Optional[str] = None
    extra: Optional[dict[str, Any]] = None

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

        raw_extra = details.get("extra") if isinstance(details.get("extra"), dict) else {}
        raw_msg = str(details.get("raw_message") or details.get("raw") or details.get("original_log") or raw_extra.get("raw_message") or "")

        # Host extraction per Stage 1. Structured text logs put the hostname
        # after the timestamp, while syslog puts it after its month/day/time.
        host = (
            details.get("host")
            or details.get("Computer")
            or details.get("computer")
            or details.get("WorkstationName")
            or details.get("hostname")
        )
        if str(host or "").casefold() in {"unknown", "unknown_host", "-"}:
            host = None
        host_inferred = bool(details.get("host_inferred", False))

        if not host:
            src_ip_cand = details.get("src_ip") or details.get("source_ip") or details.get("SourceIp")
            if src_ip_cand and src_ip_cand != "-":
                host = src_ip_cand
                host_inferred = True
            else:
                iso_log_match = re.match(
                    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+([a-zA-Z0-9_.-]+)(?:\s|$)",
                    raw_msg,
                )
                syslog_match = re.match(r"^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+([a-zA-Z0-9_\-\.]+)", raw_msg)
                host_match = iso_log_match or syslog_match
                if host_match:
                    host = host_match.group(1)
                    host_inferred = False
                else:
                    host = "unknown_host"
                    host_inferred = True

        # User extraction
        user = (
            details.get("user")
            or details.get("username")
            or details.get("TargetUserName")
            or details.get("SubjectUserName")
            or details.get("AccountName")
            or details.get("to")
        )
        if user in (None, "unknown", "-"):
            user_match = re.search(r"\buser(?:name)?=(?:\"([^\"]+)\"|([^\s]+))", raw_msg, re.IGNORECASE)
            if user_match:
                user = user_match.group(1) or user_match.group(2)
            else:
                recipient_match = re.search(r"\bto=<([^>]+)>", raw_msg, re.IGNORECASE)
                if recipient_match:
                    user = recipient_match.group(1)
        extra = details.get("extra") if isinstance(details.get("extra"), dict) else {}
        domain = details.get("TargetDomainName") or details.get("domain") or extra.get("TargetDomainName") or extra.get("domain")
        if user and domain and "\\" not in str(user) and "@" not in str(user) and str(user).casefold() not in {"system", "localsystem", "-"}:
            user = f"{domain}\\{user}"
        if user == "-":
            user = None

        # A parser may normalize an unzoned source timestamp to UTC for storage.
        # Keep that assumption explicit for the investigator UI.
        timestamp_timezone_known = True
        raw_timestamp = re.search(
            r"(?:^|\s)(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)",
            raw_msg,
        )
        syslog_timestamp = re.match(r"^[A-Z][a-z]{2}\s+\d+\s+\d{1,2}:\d{2}:\d{2}\s+", raw_msg)
        if syslog_timestamp or (raw_timestamp and not re.search(r"(?:Z|[+-]\d{2}:?\d{2})$", raw_timestamp.group(1))):
            timestamp_timezone_known = False

        # Action / summary line extraction per Stage 2
        action = (
            details.get("action")
            or details.get("message")
            or details.get("Message")
            or details.get("raw_message")
            or details.get("description")
            or ev_type
            or "System Event"
        )
        if raw_msg and str(action).casefold() in {"text_log", "text_log on unknown_host", "event"}:
            action = raw_msg

        # IP extraction
        src_ip = details.get("source_ip") or details.get("src_ip") or details.get("IpAddress") or details.get("SourceIp")
        if src_ip == "-":
            src_ip = None
        dst_ip = details.get("destination_ip") or details.get("dst_ip") or details.get("DestinationIp")

        # Port extraction
        src_port = details.get("source_port") or details.get("src_port") or details.get("SourcePort")
        dst_port = details.get("destination_port") or details.get("dst_port") or details.get("DestinationPort")

        # Process and command line extraction
        process = (
            details.get("process")
            or details.get("NewProcessName")
            or details.get("Image")
            or details.get("service_name")
        )
        parent_process = (
            details.get("parent_process")
            or details.get("ParentProcessName")
            or details.get("ParentImage")
        )
        command_line = (
            details.get("command_line")
            or details.get("CommandLine")
            or details.get("ImagePath")
        )

        # Target file and service name
        target_file = (
            details.get("target_file")
            or details.get("TargetFilename")
            or details.get("TargetObject")
            or details.get("path")
            or details.get("dst")
        )
        service_name = details.get("service_name") or details.get("ServiceName")

        # Bytes
        bytes_val = details.get("bytes")
        bytes_int = int(bytes_val) if bytes_val is not None and str(bytes_val).isdigit() else None

        is_suspicious = any(
            w in str(ev_type).lower() or w in str(action).lower() or w in str(command_line or "").lower()
            for w in ["fail", "error", "attack", "malware", "shell", "sudo", "privilege", "brute", "inject", "drop", "unauthorized", "cvlk", "rclone", "psexec", "mimikatz", "vssadmin", "ntdsutil", "comsvcs"]
        )
        severity = details.get("severity") or ("high" if is_suspicious else "low")
        raw = details.get("raw") or details.get("raw_message") or details.get("original_log") or raw_msg or str(details)

        d["source_type"] = src
        d["timestamp_timezone_known"] = timestamp_timezone_known
        d["host"] = host
        d["host_inferred"] = host_inferred
        d["source_file"] = details.get("source_file")
        d["source_record_id"] = details.get("source_record_id")
        d["event_id"] = details.get("event_id")
        d["user"] = user or "unknown"
        d["action"] = action
        d["outcome"] = details.get("outcome", "failure" if "fail" in str(ev_type).lower() or "4625" in str(action) else "success")
        d["severity"] = severity
        d["raw"] = raw
        d["src_ip"] = src_ip
        d["dst_ip"] = dst_ip
        d["src_port"] = int(src_port) if src_port is not None and str(src_port).isdigit() else None
        d["dst_port"] = int(dst_port) if dst_port is not None and str(dst_port).isdigit() else None
        d["protocol"] = details.get("protocol") or details.get("proto") or ("TCP" if dst_port else None)
        d["bytes"] = bytes_int
        d["process"] = process
        d["parent_process"] = parent_process
        d["command_line"] = command_line
        d["service_name"] = service_name
        d["target_file"] = target_file
        d["mitre_technique"] = details.get("mitre_technique")
        d["mitre_tactic"] = details.get("mitre_tactic")
        d["is_attack_path"] = bool(details.get("is_attack_path", False) or is_suspicious)
        d["attack_phase"] = details.get("attack_phase")
        d["extra"] = details.get("extra") or {}
        return d


class PaginatedEventsResponse(BaseModel):
    items: List[EventResponse]
    total: int
    limit: int
    offset: int
