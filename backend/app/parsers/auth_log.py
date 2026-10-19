# Auth log parser
import re 
from pathlib import Path

from typing import Any
from app.parsers.base_parser import BaseParser

class AuthLogParser(BaseParser):
        """Parse common Linux authentication log messages."""

        PATTERNS=[
            ("ssh_failed",re.compile(
                r"Failed password for (?:invalid user )?(?P<user>\S+) "
                r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
                ),
            ),
            (
                "ssh_success",
                re.compile(
                        
                    r"Accepted \S+ for (?P<user>\S+) from "
                    r"(?P<source_ip>\S+) port (?P<source_port>\d+)\b"

                ),
            ),
            (
                "invalid_user",
                re.compile(
                    r"Invalid user (?P<user>\S+) from (?P<source_ip>\S+)"
            ),
            ),
        ]

        def parse(self,file_path:Path,original_filename: str | None = None,)->list[dict[str,Any]]:
            records=[]

            with file_path.open("r",encoding="utf-8",errors="replace") as file:
                  for line_number, line in enumerate(file,start=1):
                        line=line.strip()

                        if not line:
                            continue

                        for event_type, pattern in self.PATTERNS:
                            match=pattern.search(line)

                            if match:
                                records.append({
                                    "event_type":event_type,
                                    "timestamp":line[:15],
                                    "source":"linux_auth",
                                    "line_number":line_number,
                                    **match.groupdict(),
                                    "raw_message":line,
                                })
                                break
            return records
    