
import re
import shlex
from pathlib import Path
from typing import Any

from app.parsers.base_parser import BaseParser


class TextFileParser(BaseParser):
    """Parse timestamped plain-text logs and structured key-value lines."""

    ISO_TIMESTAMP = re.compile(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
        r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
    )

    SYSLOG_TIMESTAMP = re.compile(
        r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"
    )

    INTEGER_FIELDS = {
        "bytes_out",
        "bytes_in",
        "destination_port",
        "status_code",
    }

    def parse(
        self,
        file_path: Path,
        original_filename: str | None = None,
    ) -> list[dict[str, Any]]:
        records = []

        with file_path.open(
            "r", encoding="utf-8-sig", errors="replace"
        ) as file:
            for line_number, line in enumerate(file, start=1):
                line = line.strip()

                if not line:
                    continue

                match = self.ISO_TIMESTAMP.search(line)
                if match is None:
                    match = self.SYSLOG_TIMESTAMP.search(line)

                timestamp = match.group(0) if match else None

                # Preserve the existing format unless this is a
                # structured key-value event.
                try:
                    tokens = shlex.split(line)
                except ValueError:
                    tokens = []

                fields = {}

                for token in tokens:
                    if "=" not in token:
                        continue

                    key, value = token.split("=", 1)

                    if key:
                        fields[key] = value

                if "event_type" not in fields:
                    records.append({
                        "timestamp": timestamp,
                        "event_type": "text_log",
                        "source": "text",
                        "line_number": line_number,
                        "raw_message": line,
                    })
                    continue

                # Convert known numeric fields to integers.
                for key in self.INTEGER_FIELDS:
                    if key in fields:
                        try:
                            fields[key] = int(fields[key])
                        except ValueError:
                            pass

                records.append({
                    **fields,
                    "timestamp": timestamp,
                    "event_type": fields.get("event_type", "text_log"),
                    "source": fields.get("source", "text"),
                    "line_number": line_number,
                    "raw_message": line,
                })

        return records
