
from pathlib import Path
from typing import Any

from app.parsers.base_parser import BaseParser
from app.parsers.auth_log import AuthLogParser
from app.parsers.web_access import WebAccessParser
from app.parsers.generic_csv_json import GenericCSVJSONParser
from app.parsers.txt_parser import TextFileParser
from app.parsers.structured_log import StructuredLogParser


class LogFileParser(BaseParser):
    """Detect and parse common .log file formats."""

    def parse(
        self,
        file_path: Path,
        original_filename: str | None = None,
    ) -> list[dict[str, Any]]:
        filename = original_filename or file_path.name

        with file_path.open(
            "r", encoding="utf-8-sig", errors="replace"
        ) as file:
            content = file.read()

        first_char = next(
            (char for char in content if not char.isspace()),
            "",
        )

        # JSON may be stored in a file ending with .log.
        if first_char in {"{", "["}:
            return GenericCSVJSONParser().parse(
                file_path,
                original_filename=filename,
            )

        auth_parser = AuthLogParser()
        web_parser = WebAccessParser()

        for line in content.splitlines():
            if not line.strip():
                continue

            if any(
                pattern.search(line)
                for _, pattern in auth_parser.PATTERNS
            ):
                return auth_parser.parse(
                    file_path,
                    original_filename=filename,
                )

            if (
                web_parser.LOG_PATTERN.search(line)
                or web_parser.is_key_value_web_log(line)
            ):
                return web_parser.parse(
                    file_path,
                    original_filename=filename,
                )

        # Fallback for other timestamped text logs.
        # Parse structured timestamped key=value logs first.
        structured_events = StructuredLogParser().parse(
            file_path,
            original_filename=filename,
        )

        if structured_events:
            return structured_events

        # Fallback for ordinary text logs.
        return TextFileParser().parse(
            file_path,
            original_filename=filename,
        )
