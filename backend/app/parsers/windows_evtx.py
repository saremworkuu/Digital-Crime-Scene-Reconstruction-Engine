
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

from Evtx.Evtx import Evtx

from app.parsers.base_parser import BaseParser


def get_element_text(parent, path, namespace):
    """Safely get the text of an XML element."""
    element = parent.find(path, namespace)

    if element is None or element.text is None:
        return None

    return element.text.strip()


def get_event_data(root, namespace):
    """Extract named fields from the Windows EventData section."""
    event_data = root.find("e:EventData", namespace)
    data = {}

    if event_data is None:
        return data

    for element in event_data.findall("e:Data", namespace):
        name = element.get("Name")
        value = element.text.strip() if element.text else None

        if name:
            data[name] = value

    return data


class WindowsEVTXParser(BaseParser):
    """Extract event records from Windows EVTX files."""

    def parse(self, file_path: Path,original_filename: str | None = None,) -> list[dict[str, Any]]:
        records = []

        with Evtx(str(file_path)) as log:
            for record_number, event in enumerate(
                log.records(), start=1
            ):
                xml = event.xml()

                try:
                    root = ET.fromstring(xml)
                except ET.ParseError:
                    continue

                namespace = {
                    "e": (
                        "http://schemas.microsoft.com/"
                        "win/2004/08/events/event"
                    )
                }

                system = root.find("e:System", namespace)

                if system is None:
                    continue

                
                provider_element = system.find("e:Provider", namespace)

                provider = (
                    provider_element.get("Name")
                    if provider_element is not None
                    else None
                )

                level = get_element_text(system, "e:Level", namespace)
                channel = get_element_text(system, "e:Channel", namespace)


                event_id_text = get_element_text(system, "e:EventID", namespace)
                event_id = (
                    int(event_id_text)
                    if event_id_text and event_id_text.isdigit()
                    else None
                )
                computer_element = system.find(
                    "e:Computer", namespace
                )
                time_element = system.find(
                    "e:TimeCreated", namespace
                )

                event_data = get_event_data(root, namespace)
                records.append({
                    "event_type": "windows_event",
                    "source": "windows_evtx",
                                        
                    "provider": provider,
                    "level": int(level) if level and level.isdigit() else None,
                    "channel": channel,
                    "event_data": event_data,

                    "record_number": record_number,
                    "timestamp": (
                        time_element.get("SystemTime")
                        if time_element is not None
                        else None
                    ),
                    "event_id": event_id,
                    "computer": (
                        computer_element.text
                        if computer_element is not None
                        else None
                    ),
                    "xml": xml,
                })

        return records
