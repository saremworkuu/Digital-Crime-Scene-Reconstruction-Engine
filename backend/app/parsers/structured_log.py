
import re
from datetime import datetime
import re
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from app.parsers.base_parser import BaseParser


class StructuredLogParser(BaseParser):
    """Parse timestamped key=value logs, file-server audit logs, and syslog formats."""

    ISO_TIMESTAMP_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    )

    SYSLOG_TIMESTAMP_PATTERN = re.compile(
        r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    )

    FIELD_PATTERN = re.compile(
        r'(?P<key>[A-Za-z0-9_]+)=(?:"(?P<quoted>[^"]*)"|<(?P<bracketed>[^>]*)>|(?P<plain>\S+))'
    )

    def parse(
        self,
        file_path: Path,
        original_filename: str | None = None,
    ) -> list[dict[str, Any]]:
        filename = original_filename or file_path.name
        events = []

        # Determine reference year for syslog logs without a year
        try:
            mtime_year = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc).year
        except Exception:
            mtime_year = 2026
        # If mtime is reasonable, use it; default to 2026
        reference_year = mtime_year if 2020 <= mtime_year <= 2030 else 2026

        with file_path.open("r", encoding="utf-8-sig", errors="replace") as file:
            lines = file.readlines()

        for line_number, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line:
                continue

            timestamp_str = None
            remainder = line
            year_inferred = False

            # Check ISO timestamp
            iso_match = self.ISO_TIMESTAMP_PATTERN.match(line)
            if iso_match:
                ts_raw = iso_match.group("timestamp").replace(" ", "T")
                if not ts_raw.endswith("Z") and "+" not in ts_raw and "-" not in ts_raw[10:]:
                    ts_raw += "Z"
                timestamp_str = ts_raw
                remainder = line[iso_match.end():].strip()
            else:
                # Check Syslog timestamp
                syslog_match = self.SYSLOG_TIMESTAMP_PATTERN.match(line)
                if syslog_match:
                    month = syslog_match.group("month")
                    day = int(syslog_match.group("day"))
                    time_part = syslog_match.group("time")
                    year_inferred = True
                    try:
                        dt = datetime.strptime(
                            f"{reference_year} {month} {day} {time_part}",
                            "%Y %b %d %H:%M:%S"
                        ).replace(tzinfo=timezone.utc)
                        timestamp_str = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                    except Exception:
                        timestamp_str = f"{reference_year}-09-{day:02d}T{time_part}Z"
                    remainder = line[syslog_match.end():].strip()

            if not timestamp_str:
                continue

            # Parse leading header tokens (e.g. host and service) before key=value pairs
            # Example 1: SRV-FS-02 FSAUDIT user=...
            # Example 2: mailgw postfix/smtp[2210]: id=...
            tokens = remainder.split()
            host = None
            service = None
            header_offset = 0

            if tokens and "=" not in tokens[0]:
                host = tokens[0]
                header_offset += len(tokens[0])
                if len(tokens) > 1 and "=" not in tokens[1]:
                    service = tokens[1].rstrip(":")
                    header_offset += 1 + len(tokens[1])

            # Extract key=value fields
            fields = {}
            for match in self.FIELD_PATTERN.finditer(remainder):
                key = match.group("key")
                val = (
                    match.group("quoted")
                    if match.group("quoted") is not None
                    else (
                        match.group("bracketed")
                        if match.group("bracketed") is not None
                        else match.group("plain")
                    )
                )
                fields[key] = val

            # Normalize extracted entities
            user = (
                fields.get("user")
                or fields.get("username")
                or fields.get("to")
                or fields.get("account")
            )
            action = (
                fields.get("action")
                or fields.get("status")
                or fields.get("cmd")
                or (f"Mail: {fields.get('subject')}" if "subject" in fields else None)
                or "log_event"
            )
            target_file = (
                fields.get("path")
                or fields.get("dst")
                or fields.get("src")
                or fields.get("attachment")
                or fields.get("file")
            )
            src_ip = fields.get("src") or fields.get("src_ip") or fields.get("client_ip")
            dst_ip = fields.get("dst") or fields.get("dst_ip") or fields.get("server_ip")

            # Formulate event_type
            event_type = "file_audit" if service == "FSAUDIT" or "path" in fields or "src" in fields else (
                "mail_gateway" if "postfix" in str(service) or "to" in fields or "subject" in fields else "structured_log"
            )

            # Build readable action description
            if service == "FSAUDIT":
                action_desc = f"FSAUDIT {action}: {target_file or ''} by {user or 'unknown'}"
            elif event_type == "mail_gateway":
                action_desc = f"Mail from <{fields.get('from', '')}> to <{fields.get('to', '')}> subject: \"{fields.get('subject', '')}\" (attach: {fields.get('attachment', '-')})"
            else:
                action_desc = f"{service or 'Event'} {action} on {host or 'system'}"

            events.append({
                "timestamp": timestamp_str,
                "host": host or "unknown_host",
                "host_inferred": False if host else True,
                "source_file": filename,
                "source_record_id": line_number,
                "event_type": event_type,
                "event_id": fields.get("id"),
                "user": user,
                "process": service,
                "parent_process": None,
                "command_line": action_desc,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": int(fields["src_port"]) if fields.get("src_port", "").isdigit() else None,
                "dst_port": int(fields["dst_port"]) if fields.get("dst_port", "").isdigit() else None,
                "protocol": fields.get("proto") or ("TCP" if "smtp" in str(service) else None),
                "bytes": int(fields["bytes"]) if fields.get("bytes", "").isdigit() else None,
                "service_name": service,
                "target_file": target_file,
                "raw": line,
                "action": action_desc,
                "extra": {
                    **fields,
                    "host": host,
                    "service": service,
                    "line_number": line_number,
                    "year_inferred": year_inferred,
                },
            })

        return events

