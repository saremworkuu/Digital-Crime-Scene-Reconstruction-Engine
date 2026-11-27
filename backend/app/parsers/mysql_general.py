"""MySQL general query log parser.

Parses MySQL general log entries of the form:
    <ISO timestamp>\t<thread_id> <Command>\t<Argument>
or:
    <ISO timestamp>\t<thread_id>\t<Command>\t<Argument>

Preserves microsecond timestamps, stores thread_id and full SQL text, maps
Connect/Quit to 'db_connect' and Query/other commands to 'db_query', and never
uses the numeric thread ID as the event host.
"""
import re
from pathlib import Path
from typing import Any

from app.parsers.base_parser import BaseParser


class MySQLGeneralLogParser(BaseParser):
    """Parse MySQL general query logs without treating thread IDs as hostnames."""

    _LINE_RE = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
        r"\t\s*(?P<thread_id>\d+)[\t ]+"
        r"(?P<rest>.*)$"
    )

    _PREAMBLE_RE = re.compile(
        r"^(?:/\S*mysqld|Tcp port:|Time\s+Id\s+Command\s+Argument)",
        re.IGNORECASE,
    )

    _TWO_WORD_COMMANDS = ("Init DB", "Change user", "Reset stmt", "Stmt close", "Binlog Dump")

    @classmethod
    def _split_command_argument(cls, rest: str) -> tuple[str, str]:
        if "\t" in rest:
            cmd, arg = rest.split("\t", 1)
            return cmd.strip(), arg
        stripped = rest.strip()
        for multi in cls._TWO_WORD_COMMANDS:
            if stripped.lower().startswith(multi.lower()):
                tail = stripped[len(multi):]
                if not tail or tail[0].isspace():
                    return multi, tail.lstrip()
        parts = stripped.split(None, 1)
        if not parts:
            return "Query", ""
        if len(parts) == 1:
            return parts[0], ""
        return parts[0], parts[1]

    @classmethod
    def looks_like_mysql_general(cls, content: str) -> bool:
        """Return True when non-empty, non-preamble lines match MySQL general log format."""
        checked = 0
        matched = 0
        for raw_line in content.splitlines():
            line = raw_line.rstrip("\r\n")
            if not line.strip() or cls._PREAMBLE_RE.match(line.strip()):
                continue
            checked += 1
            if cls._LINE_RE.match(line):
                matched += 1
            if checked >= 10:
                break
        return matched > 0 and matched == checked

    def parse(
        self,
        file_path: Path,
        original_filename: str | None = None,
    ) -> list[dict[str, Any]]:
        filename = original_filename or file_path.name
        events: list[dict[str, Any]] = []

        with file_path.open("r", encoding="utf-8-sig", errors="replace") as file:
            lines = file.readlines()

        for line_number, raw_line in enumerate(lines, start=1):
            line = raw_line.rstrip("\r\n")
            if not line.strip() or self._PREAMBLE_RE.match(line.strip()):
                continue

            match = self._LINE_RE.match(line)
            if not match:
                # Attach multi-line SQL continuation lines to the previous entry
                if events:
                    prev = events[-1]
                    cont = line
                    prev["raw"] = f"{prev['raw']}\n{cont}"
                    prev["argument"] = f"{prev['argument']}\n{cont}" if prev.get("argument") else cont
                    if prev["event_type"] == "db_query":
                        prev["sql"] = prev["argument"]
                        prev["query"] = prev["argument"]
                        prev["command_line"] = prev["argument"]
                        prev["action"] = prev["argument"][:100]
                    else:
                        prev["action"] = f"{prev['command']}: {prev['argument']}"[:159]
                continue

            ts_raw = match.group("timestamp").replace(" ", "T")
            if not ts_raw.endswith("Z") and "+" not in ts_raw and "-" not in ts_raw[10:]:
                ts_raw += "Z"

            thread_id = int(match.group("thread_id"))
            command, argument = self._split_command_argument(match.group("rest"))
            cmd_lower = command.lower()

            if cmd_lower in {"connect", "quit", "change user"}:
                event_type = "db_connect"
            else:
                event_type = "db_query"

            user = None
            if cmd_lower == "connect" and argument:
                user_match = re.match(r"^([^\s@]+)@", argument.strip())
                if user_match and user_match.group(1).lower() != "unauthenticated":
                    user = user_match.group(1)

            arg_text = argument.strip()
            if event_type == "db_query" and arg_text:
                action = arg_text[:100]
            elif arg_text:
                action = f"{command}: {arg_text}"[:159]
            else:
                action = f"MySQL {command}"[:159]

            record: dict[str, Any] = {
                "timestamp": ts_raw,
                "event_type": event_type,
                "source": "mysql_general",
                "source_file": filename,
                "source_record_id": line_number,
                "host": "unknown_host",
                "host_inferred": True,
                "thread_id": thread_id,
                "command": command,
                "argument": arg_text,
                "service_name": "mysqld",
                "action": action,
                "raw": line,
            }
            if user:
                record["user"] = user
            if event_type == "db_query":
                record["sql"] = arg_text
                record["query"] = arg_text
                if arg_text:
                    record["command_line"] = arg_text

            events.append(record)

        return events
