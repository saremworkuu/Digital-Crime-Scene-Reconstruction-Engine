
import re
import shlex
from pathlib import Path
from typing import Any

from app.parsers.base_parser import BaseParser


class WebAccessParser(BaseParser):
    """Parse Apache/Nginx access logs and key-value web logs."""

    LOG_PATTERN = re.compile(
        r'(?P<source_ip>\S+)\s+\S+\s+\S+\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status_code>\d{3})\s+(?P<response_size>\d+|-)'
    )

    WEB_IP_FIELDS = {"source_ip", "src_ip", "client_ip"}

    @staticmethod
    def _parse_key_value_line(line: str) -> dict[str, str] | None:
        """Parse a timestamp followed by key=value fields."""

        try:
            tokens = shlex.split(line)
        except ValueError:
            # Malformed quotes: preserve the original line as fallback.
            return None

        fields: dict[str, str] = {}

        for token in tokens:
            if "=" in token:
                key, value = token.split("=", 1)
                fields[key] = value
            elif re.match(r"^\d{4}-\d{2}-\d{2}T", token):
                fields.setdefault("timestamp", token)

        # Require enough fields to identify a web request.
        if not {"method", "path"}.issubset(fields):
            return None

        if not (
            WebAccessParser.WEB_IP_FIELDS.intersection(fields)
            or "status_code" in fields
            or "query_string" in fields
        ):
            return None

        # Normalize alternative IP field names.
        if "source_ip" not in fields:
            for key in ("src_ip", "client_ip"):
                if fields.get(key):
                    fields["source_ip"] = fields[key]
                    break

        return fields

    def is_key_value_web_log(self, line: str) -> bool:
        """Check whether a line resembles a key-value web request."""

        return self._parse_key_value_line(line) is not None

    def parse(
        self,
        file_path: Path,
        original_filename: str | None = None,
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []

        with file_path.open(
            "r",
            encoding="utf-8-sig",
            errors="replace",
        ) as file:
            for line_number, raw_line in enumerate(file, start=1):
                line = raw_line.strip()

                if not line:
                    continue

                # First, try the standard Apache/Nginx format.
                match = self.LOG_PATTERN.search(line)

                if match:
                    record: dict[str, Any] = match.groupdict()
                    record["event_type"] = "web_access"
                    record["source"] = "web_server"
                    record["line_number"] = line_number

                    record["status_code"] = int(record["status_code"])

                    if record["response_size"] != "-":
                        record["response_size"] = int(
                            record["response_size"]
                        )

                    records.append(record)
                    continue

                # Next, try timestamped key-value web logs.
                record = self._parse_key_value_line(line)

                if record is not None:
                    record["event_type"] = "web_access"
                    record.setdefault("source", "web_server")
                    record["line_number"] = line_number

                    record["method"] = record["method"].upper()

                    if record.get("status_code"):
                        try:
                            record["status_code"] = int(
                                record["status_code"]
                            )
                        except ValueError:
                            pass

                    records.append(record)
                    continue

                # Fallback: do not discard unrecognized log lines.
                records.append({
                    "event_type": "text_log",
                    "source": "text_file",
                    "line_number": line_number,
                    "raw_message": line,
                })

        return records
