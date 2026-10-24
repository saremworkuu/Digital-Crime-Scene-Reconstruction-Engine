import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


def normalize_timestamp(record: dict[str, Any]) -> str | None:
    """
    Convert a record's timestamp to UTC in this format:
    YYYY-MM-DDTHH:MM:SSZ
    """
    # PCAP records use Unix timestamps.
    value = record.get("first_timestamp")

    if value is not None:
        try:
            timestamp = datetime.fromtimestamp(
                float(value), tz=timezone.utc
            )
            return timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError, OverflowError, OSError):
            pass

    value = record.get("timestamp")

    if value is None or value == "":
        return None

    try:
        if isinstance(value, (int, float)):
            timestamp = datetime.fromtimestamp(
                float(value), tz=timezone.utc
            )
        else:
            text = str(value).strip()

            # Handle Linux syslog timestamps: "Oct 14 08:30:00" or "Sep  3 02:14:10"
            if re.fullmatch(
                r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
                text,
            ):
                current_year = 2026
                timestamp = datetime.strptime(
                    f"{current_year} {text}",
                    "%Y %b %d %H:%M:%S",
                ).replace(tzinfo=timezone.utc)
            else:
                timestamp = datetime.fromisoformat(
                    text.replace("Z", "+00:00")
                )

                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)

                timestamp = timestamp.astimezone(timezone.utc)

        return timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

    except (TypeError, ValueError, OverflowError, OSError):
        return None


def normalize_record(record: dict[str, Any], default_filename: str = "") -> dict[str, Any]:
    """
    Convert one parser record into the common DCSRE event format with all canonical fields.
    """
    timestamp = normalize_timestamp(record)

    # 1. Host resolution per Stage 1
    host = (
        record.get("host")
        or record.get("computer")
        or record.get("Computer")
        or record.get("hostname")
        or record.get("WorkstationName")
    )
    host_inferred = record.get("host_inferred")

    if not host:
        # Check src_ip for flow/network records
        src_ip = record.get("src_ip") or record.get("source_ip") or record.get("SourceIp")
        if src_ip:
            host = src_ip
            host_inferred = True
        else:
            # Fallback only when record truly has no host
            host = "unknown_host"
            host_inferred = True
    elif host_inferred is None:
        host_inferred = False

    # 2. Canonical field extraction per Stage 2
    source_file = record.get("source_file") or default_filename
    source_record_id = (
        record.get("source_record_id")
        or record.get("record_number")
        or record.get("line_number")
        or record.get("packet_number")
    )
    event_type = record.get("event_type", "event")
    event_id = record.get("event_id")
    user = (
        record.get("user")
        or record.get("username")
        or record.get("TargetUserName")
        or record.get("SubjectUserName")
        or record.get("to")
    )
    if user == "-":
        user = None

    process = (
        record.get("process")
        or record.get("Image")
        or record.get("NewProcessName")
        or record.get("service_name")
    )
    parent_process = (
        record.get("parent_process")
        or record.get("ParentImage")
        or record.get("ParentProcessName")
    )
    command_line = (
        record.get("command_line")
        or record.get("CommandLine")
        or record.get("ImagePath")
    )
    src_ip = record.get("src_ip") or record.get("source_ip") or record.get("SourceIp")
    if src_ip == "-":
        src_ip = None
    dst_ip = record.get("dst_ip") or record.get("destination_ip") or record.get("DestinationIp")

    src_port = record.get("src_port") or record.get("source_port")
    src_port_int = int(src_port) if src_port is not None and str(src_port).isdigit() else None

    dst_port = record.get("dst_port") or record.get("destination_port")
    dst_port_int = int(dst_port) if dst_port is not None and str(dst_port).isdigit() else None

    protocol = record.get("protocol") or record.get("proto") or ("TCP" if dst_port_int else None)
    bytes_val = record.get("bytes")
    bytes_int = int(bytes_val) if bytes_val is not None and str(bytes_val).isdigit() else None

    service_name = record.get("service_name") or record.get("ServiceName")
    target_file = (
        record.get("target_file")
        or record.get("TargetFilename")
        or record.get("TargetObject")
        or record.get("path")
        or record.get("dst")
    )
    raw = record.get("raw") or record.get("raw_message") or str(record)
    action = record.get("action") or f"{event_type} on {host}"

    extra = record.get("extra")
    if not isinstance(extra, dict):
        extra = {
            k: v for k, v in record.items()
            if k not in {
                "timestamp", "host", "host_inferred", "source_file", "source_record_id",
                "event_type", "event_id", "user", "process", "parent_process",
                "command_line", "src_ip", "dst_ip", "src_port", "dst_port",
                "protocol", "bytes", "service_name", "target_file", "raw", "action"
            }
        }

    details = {
        "host": host,
        "host_inferred": host_inferred,
        "source_file": source_file,
        "source_record_id": source_record_id,
        "event_id": event_id,
        "user": user,
        "process": process,
        "parent_process": parent_process,
        "command_line": command_line,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port_int,
        "dst_port": dst_port_int,
        "protocol": protocol,
        "bytes": bytes_int,
        "service_name": service_name,
        "target_file": target_file,
        "raw": raw,
        "action": action,
        "extra": extra,
        # Preserve original fields for backward compatibility
        **{k: v for k, v in record.items() if k not in {"timestamp", "details"}},
    }

    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "source": record.get("source") or Path(source_file or "").suffix.lstrip(".").lower() or "log",
        "details": details,
    }


def normalize_records(
    records: list[dict[str, Any]],
    default_filename: str = "",
) -> list[dict[str, Any]]:
    """Normalize multiple records, skipping invalid timestamps."""
    normalized = []

    for record in records:
        event = normalize_record(record, default_filename=default_filename)

        if event["timestamp"] is None:
            continue

        normalized.append(event)

    return normalized

