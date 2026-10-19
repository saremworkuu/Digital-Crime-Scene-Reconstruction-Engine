
from pathlib import Path

from app.parsers.auth_log import AuthLogParser
from app.parsers.generic_csv_json import GenericCSVJSONParser
from app.parsers.log_parser import LogFileParser
from app.parsers.txt_parser import TextFileParser
from app.parsers.web_access import WebAccessParser
from app.parsers.pcap import PCAPParser
from app.parsers.pcapng import PCAPNGParser
from app.parsers.windows_evtx import WindowsEVTXParser


def get_parser(
    file_path: Path,
    original_filename: str | None = None,
):
    """Select a parser using the original filename extension."""

    filename = original_filename or file_path.name
    extension = Path(filename).suffix.lower()

    if extension == ".csv" or extension == ".json":
        return GenericCSVJSONParser()

    if extension == ".log":
        return LogFileParser()

    if extension == ".txt":
        return TextFileParser()

    if extension == ".auth":
        return AuthLogParser()

    if extension == ".access":
        return WebAccessParser()

    if extension == ".pcap":
        return PCAPParser()

    if extension == ".pcapng":
        return PCAPNGParser()

    if extension == ".evtx":
        return WindowsEVTXParser()

    return None
