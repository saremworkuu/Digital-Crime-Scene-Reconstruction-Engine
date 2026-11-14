# Auth log parser
import re 
from pathlib import Path
from typing import Any
from app.parsers.base_parser import BaseParser

class AuthLogParser(BaseParser):
    """Parse common Linux authentication log messages with host extraction."""

    SYSLOG_LINE = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>[A-Za-z0-9_\-\.]+)\s+"
        r"(?P<service>[a-zA-Z0-9_\-\.\/]+)(?:\[\d+\])?:\s+"
        r"(?P<message>.*)$"
    )

    PATTERNS = [
        ("ssh_failed", re.compile(
            r"Failed password for (?:invalid user )?(?P<user>\S+) "
            r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
        )),
        ("ssh_success", re.compile(
            r"Accepted \S+ for (?P<user>\S+) from "
            r"(?P<source_ip>\S+) port (?P<source_port>\d+)\b"
        )),
        ("invalid_user", re.compile(
            r"Invalid user (?P<user>\S+) from (?P<source_ip>\S+)"
        )),
        ("sudo_command", re.compile(
            r"\b(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)$"
        )),
    ]

    def parse(self, file_path: Path, original_filename: str | None = None) -> list[dict[str, Any]]:
        filename = original_filename or file_path.name
        records = []

        with file_path.open("r", encoding="utf-8", errors="replace") as file:
            for line_number, line in enumerate(file, start=1):
                line = line.strip()
                if not line:
                    continue

                host = None
                service = None
                msg_body = line
                timestamp = line[:15]

                hdr_match = self.SYSLOG_LINE.match(line)
                if hdr_match:
                    timestamp = hdr_match.group("timestamp")
                    host = hdr_match.group("host")
                    service = hdr_match.group("service")
                    msg_body = hdr_match.group("message")

                matched = False
                for event_type, pattern in self.PATTERNS:
                    match = pattern.search(msg_body)
                    if match:
                        g = match.groupdict()
                        user = g.get("user")
                        src_ip = g.get("source_ip")
                        src_port = int(g["source_port"]) if g.get("source_port", "").isdigit() else None
                        cmd = g.get("command")

                        action = f"{service or 'auth'}: {event_type} for {user or 'unknown'}"
                        if src_ip:
                            action += f" from {src_ip}"
                        if cmd:
                            action += f" command: {cmd}"

                        records.append({
                            "timestamp": timestamp,
                            "host": host or "unknown_host",
                            "host_inferred": False if host else True,
                            "source_file": filename,
                            "source_record_id": line_number,
                            "event_type": event_type,
                            "event_id": None,
                            "user": user,
                            "process": service,
                            "parent_process": None,
                            "command_line": cmd,
                            "src_ip": src_ip,
                            "source_ip": src_ip,
                            "source": "linux_auth",
                            "dst_ip": None,
                            "src_port": src_port,
                            "dst_port": 22 if "ssh" in (service or "") else None,
                            "protocol": "TCP" if src_port else None,
                            "bytes": None,
                            "service_name": service,
                            "target_file": None,
                            "raw": line,
                            "action": action,
                            "extra": {
                                **g,
                                "line_number": line_number,
                                "raw_message": line,
                                "year_inferred": True,
                            },
                        })
                        matched = True
                        break

                if not matched and hdr_match:
                    records.append({
                        "timestamp": timestamp,
                        "host": host or "unknown_host",
                        "host_inferred": False if host else True,
                        "source_file": filename,
                        "source_record_id": line_number,
                        "event_type": "linux_auth",
                        "event_id": None,
                        "user": None,
                        "process": service,
                        "parent_process": None,
                        "command_line": None,
                        "src_ip": None,
                        "dst_ip": None,
                        "src_port": None,
                        "dst_port": None,
                        "protocol": None,
                        "bytes": None,
                        "service_name": service,
                        "target_file": None,
                        "raw": line,
                        "action": f"{service}: {msg_body[:80]}",
                        "extra": {"line_number": line_number, "raw_message": line, "year_inferred": True},
                    })

        return records

    