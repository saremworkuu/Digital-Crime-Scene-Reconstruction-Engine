
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from app.parsers.base_parser import BaseParser


class StructuredLogParser(BaseParser):
    """Parse timestamped key=value logs."""

    TIMESTAMP_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T"
        r"\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
    )

    FIELD_PATTERN = re.compile(
        r'(?P<key>[A-Za-z_][A-Za-z0-9_]*)='
        r'(?:"(?P<quoted>[^"]*)"|(?P<plain>\S+))'
    )

    def parse(
        self,
        file_path: Path,
        original_filename: str | None = None,
    ) -> list[dict[str, Any]]:
        events = []

        with file_path.open(
            "r", encoding="utf-8-sig", errors="replace"
        ) as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue

            timestamp_match = self.TIMESTAMP_PATTERN.match(line)
            if not timestamp_match:
                continue

            timestamp_text = timestamp_match.group("timestamp")
            timestamp_text = timestamp_text.replace("Z", "+00:00")

            try:
                timestamp = datetime.fromisoformat(timestamp_text)
            except ValueError:
                continue

            fields = {}

            for match in self.FIELD_PATTERN.finditer(
                line[timestamp_match.end():]
            ):
                value = (
                    match.group("quoted")
                    if match.group("quoted") is not None
                    else match.group("plain")
                )
                fields[match.group("key")] = value

            event_type = fields.pop("event_type", None)

            if not event_type:
                continue

            events.append({
                "timestamp": timestamp,
                "event_type": event_type,
                "source": fields.pop("source", "text"),
                "details": {
                    **fields,
                    "line_number": line_number,
                },
            })

        return events
