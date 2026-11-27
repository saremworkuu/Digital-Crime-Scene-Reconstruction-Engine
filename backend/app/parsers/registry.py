from pathlib import Path
import xml.etree.ElementTree as ET

from app.parsers.auth_log import AuthLogParser
from app.parsers.generic_csv_json import GenericCSVJSONParser
from app.parsers.log_parser import LogFileParser
from app.parsers.txt_parser import TextFileParser
from app.parsers.web_access import WebAccessParser


def _is_vuln_scan_xml(file_path: Path) -> bool:
    """Return True only when the XML file root tag is VulnScan."""
    try:
        for _, elem in ET.iterparse(file_path, events=("start",)):
            return elem.tag.split("}")[-1] == "VulnScan"
    except Exception:
        return False
    return False


def _is_auditd_file(filename: str) -> bool:
    """Return True when the filename strongly suggests a Linux auditd log."""
    lower = filename.lower()
    return (
        "audit" in lower
        or lower.endswith(".audit")
        or lower.endswith(".auditd")
    )


def get_parser(
    file_path: Path,
    original_filename: str | None = None,
):
    """Select a parser using the original filename extension with resilient dynamic loading."""

    filename = original_filename or file_path.name
    extension = Path(filename).suffix.lower()
    lower_name = filename.lower()

    # ------------------------------------------------------------------ #
    # Auditd: checked before generic .log routing so it always wins       #
    # ------------------------------------------------------------------ #
    if _is_auditd_file(filename):
        try:
            from app.parsers.auditd import AuditdParser
            return AuditdParser()
        except Exception:
            return LogFileParser()

    if extension in (".csv", ".json"):
        return GenericCSVJSONParser()

    if "mysql" in lower_name:
        try:
            from app.parsers.mysql_general import MySQLGeneralLogParser
            return MySQLGeneralLogParser()
        except Exception:
            pass

    if extension == ".log":
        # Check if it looks like an auth log or access log by filename
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

    if extension == ".xml":
        if file_path and file_path.is_file() and _is_vuln_scan_xml(file_path):
            try:
                from app.parsers.vuln_scan import VulnScanParser
                return VulnScanParser()
            except Exception:
                pass
        try:
            from app.parsers.windows_evtx import WindowsEVTXParser
            return WindowsEVTXParser()
        except Exception:
            return TextFileParser()

    if extension == ".pcap":
        try:
            from app.parsers.pcap import PCAPParser
            return PCAPParser()
        except Exception:
            # Fallback to generic log/txt parser if scapy is not installed
            return LogFileParser()

    if extension == ".pcapng":
        try:
            from app.parsers.pcapng import PCAPNGParser
            return PCAPNGParser()
        except Exception:
            return LogFileParser()

    if extension == ".evtx":
        try:
            from app.parsers.windows_evtx import WindowsEVTXParser
            return WindowsEVTXParser()
        except Exception:
            # Fallback to JSON/CSV if exported, or text
            return GenericCSVJSONParser()

    return None
