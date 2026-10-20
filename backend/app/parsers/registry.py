from pathlib import Path

from app.parsers.auth_log import AuthLogParser
from app.parsers.generic_csv_json import GenericCSVJSONParser
from app.parsers.log_parser import LogFileParser
from app.parsers.txt_parser import TextFileParser
from app.parsers.web_access import WebAccessParser


def get_parser(
    file_path: Path,
    original_filename: str | None = None,
):
    """Select a parser using the original filename extension with resilient dynamic loading."""

    filename = original_filename or file_path.name
    extension = Path(filename).suffix.lower()

    if extension in (".csv", ".json"):
        return GenericCSVJSONParser()

    if extension == ".log":
        # Check if it looks like an auth log or access log by filename
        lower_name = filename.lower()
        if "auth" in lower_name or "secure" in lower_name:
            return AuthLogParser()
        if "access" in lower_name or "nginx" in lower_name or "apache" in lower_name or "web" in lower_name:
            return WebAccessParser()
        return LogFileParser()

    if extension == ".txt":
        return TextFileParser()

    if extension == ".auth":
        return AuthLogParser()

    if extension == ".access":
        return WebAccessParser()

    if extension == ".pcap":
        try:
            from app.parsers.pcap import PCAPParser
            return PCAPParser()
        except ImportError:
            # Fallback to generic log/txt parser if scapy is not installed
            return LogFileParser()

    if extension == ".pcapng":
        try:
            from app.parsers.pcapng import PCAPNGParser
            return PCAPNGParser()
        except ImportError:
            return LogFileParser()

    if extension == ".evtx":
        try:
            from app.parsers.windows_evtx import WindowsEVTXParser
            return WindowsEVTXParser()
        except ImportError:
            # Fallback to JSON/CSV if exported, or text
            return GenericCSVJSONParser()

    return None
