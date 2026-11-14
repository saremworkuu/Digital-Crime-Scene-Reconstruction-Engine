"""
auditd log parser — groups lines sharing the same msg=audit(ts:serial) into
one DCSRE event.  SYSCALL + EXECVE lines are combined; a0..aN are assembled
into command_line.
"""
import re
from pathlib import Path
from typing import Any

from app.parsers.base_parser import BaseParser


# msg=audit(1721609400.123:456): ...
_MSG_HEADER = re.compile(
    r"^(?:type=(\w+)\s+)?msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)"
)

# a0="cmd" a1="arg1" a2="arg2" ... or a0=cmd
_ARG_RE = re.compile(r'\ba(\d+)=(?:"([^"]*)"|(\S+))')

# uid=1000 user=www-data pid=12345 ...
_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([\S]+))')


def _kv(text: str) -> dict:
    result = {}
    for m in _KV_RE.finditer(text):
        result[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return result


def _build_cmdline(fields: dict) -> str | None:
    """Reconstruct command line from a0..aN fields."""
    args = []
    i = 0
    while True:
        key = f"a{i}"
        if key not in fields:
            break
        args.append(fields[key])
        i += 1
    return " ".join(args) if args else None


class AuditdParser(BaseParser):
    """Parse Linux auditd logs, grouping multi-line records by (timestamp, serial)."""

    def parse(self, file_path: Path, original_filename: str | None = None) -> list[dict[str, Any]]:
        filename = original_filename or file_path.name

        # Group lines by (unix_ts, serial)
        groups: dict[tuple, list[tuple[str, str]]] = {}

        with file_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                m = _MSG_HEADER.match(line)
                if not m:
                    continue
                rec_type = m.group(1) or "UNKNOWN"
                unix_ts = m.group(2)
                serial = m.group(3)
                body = m.group(4)
                key = (unix_ts, serial)
                groups.setdefault(key, []).append((rec_type, body))

        events = []
        for record_number, ((unix_ts, serial), parts) in enumerate(groups.items(), start=1):
            # Merge all KV fields from all parts
            merged: dict[str, str] = {}
            types_seen: list[str] = []
            for rec_type, body in parts:
                types_seen.append(rec_type)
                merged.update(_kv(body))

            # Reconstruct command line from execve args
            cmd = _build_cmdline(merged)

            # Interpret timestamp
            try:
                from datetime import datetime, timezone
                ts_dt = datetime.fromtimestamp(float(unix_ts), tz=timezone.utc)
                timestamp_str = ts_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                timestamp_str = None

            exe = merged.get("exe") or merged.get("a0")
            user = (
                merged.get("uid")
                or merged.get("auid")
                or merged.get("user")
                or merged.get("acct")
            )
            # Prefer named user over UID numbers
            for ukey in ("acct", "subj", "comm"):
                if merged.get(ukey) and not merged[ukey].isdigit():
                    user = merged[ukey]
                    break

            host = merged.get("hostname") or merged.get("node") or "unknown_host"
            syscall_name = merged.get("syscall")
            pid = merged.get("pid")

            action_parts = [t for t in types_seen if t not in ("UNKNOWN",)]
            action = f"auditd {'/'.join(action_parts)}"
            if syscall_name:
                action += f" syscall={syscall_name}"
            if cmd:
                action += f": {cmd[:80]}"
            elif exe:
                action += f": {exe}"

            events.append({
                "timestamp": timestamp_str,
                "host": host,
                "host_inferred": host == "unknown_host",
                "source_file": filename,
                "source_record_id": record_number,
                "event_type": "auditd",
                "event_id": serial,
                "user": user if user and user not in ("-", "4294967295", "unset") else None,
                "process": exe,
                "parent_process": None,
                "command_line": cmd,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "protocol": None,
                "bytes": None,
                "service_name": None,
                "target_file": merged.get("name") or merged.get("path"),
                "raw": " | ".join(b for _, b in parts),
                "action": action,
                "extra": {
                    **merged,
                    "serial": serial,
                    "unix_ts": unix_ts,
                    "record_types": types_seen,
                    "pid": pid,
                    "syscall": syscall_name,
                },
            })

        return events
