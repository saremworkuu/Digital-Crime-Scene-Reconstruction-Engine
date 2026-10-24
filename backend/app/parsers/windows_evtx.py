import re
from pathlib import Path
from typing import Any, Optional
import xml.etree.ElementTree as ET

try:
    from Evtx.Evtx import Evtx
    HAVE_EVTX = True
except ImportError:
    HAVE_EVTX = False
    Evtx = None

from app.parsers.base_parser import BaseParser


def _get_element_text(parent: ET.Element, tag: str, namespace: Optional[dict] = None) -> Optional[str]:
    """Safely get stripped text of an XML element with or without namespace."""
    elem = parent.find(tag, namespace) if namespace else parent.find(tag)
    if elem is None:
        # Try local tag lookup ignoring namespace
        clean_tag = tag.split(":")[-1]
        for child in parent:
            if child.tag.split("}")[-1] == clean_tag:
                elem = child
                break
    if elem is not None and elem.text:
        return elem.text.strip()
    return None


def _extract_event_data(root: ET.Element, namespace: Optional[dict] = None) -> dict[str, Any]:
    """Extract named fields from EventData or UserData."""
    data: dict[str, Any] = {}
    event_data = root.find("e:EventData", namespace) if namespace else root.find("EventData")
    if event_data is None:
        for child in root:
            if child.tag.split("}")[-1] in ("EventData", "UserData"):
                event_data = child
                break

    if event_data is not None:
        for element in event_data:
            name = element.get("Name") or element.tag.split("}")[-1]
            val = element.text.strip() if element.text else ""
            if name and name != "Data":
                data[name] = val
            elif element.get("Name"):
                data[element.get("Name")] = val
    return data


def _build_action_summary(
    event_id: Optional[int],
    process: Optional[str],
    parent_process: Optional[str],
    user: Optional[str],
    cmd: Optional[str],
    target_file: Optional[str],
    service: Optional[str],
    event_data: dict[str, Any],
) -> str:
    """Build a concise, informative timeline card summary line."""
    p_name = Path(process.replace("\\", "/")).name if process else ""
    pp_name = Path(parent_process.replace("\\", "/")).name if parent_process else ""
    u_name = user or "SYSTEM"

    if event_id in (4688, 1):
        summary = f"{event_id} process created: {p_name}"
        if pp_name:
            summary += f" (parent {pp_name})"
        if u_name and u_name != "-":
            summary += f" by {u_name}"
        return summary

    if event_id == 4624:
        logon_type = event_data.get("LogonType", "")
        type_str = f" (type {logon_type})" if logon_type else ""
        return f"4624 successful logon: {u_name}{type_str}"

    if event_id == 4625:
        status = event_data.get("Status", "")
        return f"4625 failed logon: {u_name} (status {status})"

    if event_id == 4672:
        privs = event_data.get("PrivilegeList", "")
        return f"4672 special privileges assigned to {u_name}: {privs[:60]}"

    if event_id in (7045, 4697):
        svc_name = service or event_data.get("ServiceName", "service")
        return f"{event_id} service installed: {svc_name} by {u_name}"

    if event_id in (1102, 104):
        return f"{event_id} audit log cleared by {u_name}"

    if event_id == 22:
        qname = event_data.get("QueryName", "")
        qres = event_data.get("QueryResults", "")
        return f"Sysmon 22 DNS query: {qname} -> {qres}"

    if event_id == 3:
        dst = event_data.get("DestinationIp", "")
        dport = event_data.get("DestinationPort", "")
        return f"Sysmon 3 network connection: {p_name} -> {dst}:{dport}"

    if event_id in (11, 23):
        fname = Path(str(target_file or "").replace("\\", "/")).name
        action = "file created" if event_id == 11 else "file deleted"
        return f"Sysmon {event_id} {action}: {fname} by {p_name}"

    if event_id == 13:
        tobj = event_data.get("TargetObject", "")
        return f"Sysmon 13 registry value set: {tobj}"

    if event_id == 10:
        s_img = Path(str(event_data.get("SourceImage", "")).replace("\\", "/")).name
        t_img = Path(str(event_data.get("TargetImage", "")).replace("\\", "/")).name
        return f"Sysmon 10 process access: {s_img} accessed {t_img}"

    if cmd:
        return f"Windows Event {event_id or ''}: {cmd[:80]}"
    return f"Windows Event {event_id or ''} on {event_data.get('Computer', 'host')}"


def _parse_xml_event_element(
    event_elem: ET.Element,
    record_number: int,
    source_file: str,
    raw_xml: str = "",
) -> dict[str, Any]:
    """Normalizes one XML <Event> element (from EVTX XML or .xml file) into DCSRE schema."""
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    system = event_elem.find("e:System", namespace)
    if system is None:
        system = event_elem.find("System")
        namespace = {}

    provider = None
    level = None
    channel = None
    event_id = None
    computer = None
    timestamp = None

    if system is not None:
        prov = system.find("e:Provider", namespace) if namespace else system.find("Provider")
        provider = prov.get("Name") if prov is not None else None

        lvl_txt = _get_element_text(system, "e:Level" if namespace else "Level", namespace)
        level = int(lvl_txt) if lvl_txt and lvl_txt.isdigit() else None

        channel = _get_element_text(system, "e:Channel" if namespace else "Channel", namespace)

        eid_txt = _get_element_text(system, "e:EventID" if namespace else "EventID", namespace)
        event_id = int(eid_txt) if eid_txt and eid_txt.isdigit() else None

        computer = _get_element_text(system, "e:Computer" if namespace else "Computer", namespace)

        time_elem = system.find("e:TimeCreated", namespace) if namespace else system.find("TimeCreated")
        if time_elem is not None:
            timestamp = time_elem.get("SystemTime")

    event_data = _extract_event_data(event_elem, namespace)

    # Field mapping
    process = (
        event_data.get("NewProcessName")
        or event_data.get("Image")
        or event_data.get("ProcessName")
    )
    parent_process = (
        event_data.get("ParentProcessName")
        or event_data.get("ParentImage")
    )
    command_line = (
        event_data.get("CommandLine")
        or event_data.get("ImagePath")
        or event_data.get("ProcessCommandLine")
    )
    user = (
        event_data.get("TargetUserName")
        or event_data.get("User")
        or event_data.get("SubjectUserName")
        or event_data.get("AccountName")
    )
    if user == "-":
        user = event_data.get("SubjectUserName") if event_data.get("SubjectUserName") != "-" else None

    src_ip = (
        event_data.get("IpAddress")
        or event_data.get("SourceIp")
        or event_data.get("SourceAddress")
    )
    if src_ip == "-":
        src_ip = None

    dst_ip = event_data.get("DestinationIp") or event_data.get("DestAddress")
    
    src_port = event_data.get("SourcePort") or event_data.get("IpPort")
    src_port_int = int(src_port) if src_port and str(src_port).isdigit() else None

    dst_port = event_data.get("DestinationPort")
    dst_port_int = int(dst_port) if dst_port and str(dst_port).isdigit() else None

    service_name = event_data.get("ServiceName")
    target_file = (
        event_data.get("TargetFilename")
        or event_data.get("TargetObject")
        or event_data.get("FileName")
    )

    action = _build_action_summary(
        event_id,
        process,
        parent_process,
        user,
        command_line,
        target_file,
        service_name,
        event_data,
    )

    return {
        "timestamp": timestamp,
        "host": computer or "unknown_host",
        "host_inferred": False if computer else True,
        "source_file": source_file,
        "source_record_id": record_number,
        "event_type": "windows_event",
        "event_id": event_id,
        "user": user,
        "process": process,
        "parent_process": parent_process,
        "command_line": command_line,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port_int,
        "dst_port": dst_port_int,
        "protocol": event_data.get("Protocol", "TCP" if dst_port_int else None),
        "bytes": int(event_data["Bytes"]) if event_data.get("Bytes", "").isdigit() else None,
        "service_name": service_name,
        "target_file": target_file,
        "raw": raw_xml or ET.tostring(event_elem, encoding="unicode"),
        "xml": raw_xml or ET.tostring(event_elem, encoding="unicode"),
        "source": "windows_evtx",
        "record_number": record_number,
        "action": action,
        "extra": {
            **event_data,
            "provider": provider,
            "channel": channel,
            "level": level,
            "computer": computer,
            "record_number": record_number,
        },
    }


class WindowsEVTXParser(BaseParser):
    """Extract event records from Windows EVTX and Sysmon XML files."""

    def parse(self, file_path: Path, original_filename: str | None = None) -> list[dict[str, Any]]:
        filename = original_filename or file_path.name
        ext = Path(filename).suffix.lower()

        # Check if the file is plain XML or begins with XML tags
        is_xml_text = False
        try:
            with file_path.open("rb") as f:
                header = f.read(512).strip()
                if header.startswith(b"<?xml") or header.startswith(b"<Events") or header.startswith(b"<Event") or ext == ".xml":
                    is_xml_text = True
        except Exception:
            pass

        if is_xml_text:
            return self._parse_xml(file_path, filename)

        if not HAVE_EVTX:
            raise RuntimeError("python-evtx is required for EVTX parsing. Please install python-evtx.")

        records = []
        with Evtx(str(file_path)) as log:
            for record_number, event in enumerate(log.records(), start=1):
                try:
                    xml_str = event.xml()
                    root = ET.fromstring(xml_str)
                    record = _parse_xml_event_element(root, record_number, filename, xml_str)
                    records.append(record)
                except Exception:
                    continue

        return records

    def _parse_xml(self, file_path: Path, filename: str) -> list[dict[str, Any]]:
        """Parses an XML file containing one or more <Event> elements."""
        records = []
        try:
            tree = ET.parse(str(file_path))
            root = tree.getroot()
        except ET.ParseError:
            # Try wrapping multiple root events or sanitizing
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                wrapped = f"<EventsContainer>{content}</EventsContainer>"
                root = ET.fromstring(wrapped)
            except Exception as e:
                raise ValueError(f"Invalid XML in {filename}: {e}")

        # Find all <Event> elements
        event_elements = root.findall(".//Event")
        if not event_elements:
            event_elements = [child for child in root if child.tag.split("}")[-1] == "Event"]
        if not event_elements and root.tag.split("}")[-1] == "Event":
            event_elements = [root]

        for record_number, elem in enumerate(event_elements, start=1):
            rec_id = _get_element_text(elem, ".//EventRecordID")
            rec_num = int(rec_id) if rec_id and rec_id.isdigit() else record_number
            raw_str = ET.tostring(elem, encoding="unicode")
            record = _parse_xml_event_element(elem, rec_num, filename, raw_str)
            records.append(record)

        return records

