import re
from pathlib import Path
from typing import Any, Optional
import xml.etree.ElementTree as ET

from app.parsers.base_parser import BaseParser


_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _element_text(parent: ET.Element, tag: str) -> Optional[str]:
    clean = tag.split(":")[-1]
    for child in parent:
        if child.tag.split("}")[-1] == clean and child.text and child.text.strip():
            return child.text.strip()
    return None


class VulnScanParser(BaseParser):
    """Parse <VulnScan> XML vulnerability scan exports as pre-incident context events."""

    def parse(
        self,
        file_path: Path,
        original_filename: str | None = None,
    ) -> list[dict[str, Any]]:
        filename = original_filename or file_path.name
        tree = ET.parse(file_path)
        root = tree.getroot()
        if root.tag.split("}")[-1] != "VulnScan":
            return []

        root_date = root.get("date")
        scanner = root.get("scanner") or "VulnScan"
        records: list[dict[str, Any]] = []
        rec_num = 0

        # Walk Host -> Finding (or fallback Finding anywhere under root)
        hosts = [el for el in root if el.tag.split("}")[-1] == "Host"]
        host_groups: list[tuple[Optional[str], Optional[str], list[ET.Element]]] = []
        if hosts:
            for host_el in hosts:
                h_name = host_el.get("name") or host_el.get("hostname") or host_el.get("host")
                h_ip = host_el.get("ip") or host_el.get("address")
                findings = [f for f in host_el.iter() if f.tag.split("}")[-1] == "Finding"]
                host_groups.append((h_name, h_ip, findings))
        else:
            findings = [f for f in root.iter() if f.tag.split("}")[-1] == "Finding"]
            host_groups.append((None, None, findings))

        for host_name, host_ip, findings in host_groups:
            for elem in findings:
                rec_num += 1
                finding_id = elem.get("id") or str(rec_num)
                title = _element_text(elem, "Title") or _element_text(elem, "title") or elem.get("title") or f"Finding {finding_id}"
                severity = (elem.get("severity") or _element_text(elem, "severity") or "medium").strip().lower()
                status_val = (elem.get("status") or _element_text(elem, "status") or "open").strip().lower()
                ticket = elem.get("ticket") or _element_text(elem, "ticket")
                first_detected = (
                    elem.get("first_detected")
                    or _element_text(elem, "first_detected")
                    or elem.get("date")
                    or root_date
                )
                date_only = bool(first_detected and _DATE_ONLY_RE.fullmatch(first_detected.strip()))
                ts = f"{first_detected.strip()}T00:00:00Z" if date_only else first_detected

                host = (host_name or elem.get("host") or "unknown_host").strip()
                raw_xml = ET.tostring(elem, encoding="unicode")
                action = f"[{finding_id}] {title} ({status_val})"

                records.append({
                    "timestamp": ts,
                    "timestamp_inferred": first_detected is None,
                    "host": host,
                    "host_inferred": host == "unknown_host",
                    "source_file": filename,
                    "source_record_id": rec_num,
                    "event_type": "vuln_scan",
                    "source": "vuln_scan",
                    "event_id": finding_id,
                    "category": "context",
                    "severity": severity,
                    "status": status_val,
                    "ticket": ticket,
                    "first_detected": first_detected,
                    "date_only": date_only,
                    "is_attack_path": False,
                    "user": None,
                    "process": None,
                    "parent_process": None,
                    "command_line": None,
                    "src_ip": None,
                    "dst_ip": None,
                    "raw": raw_xml,
                    "action": action,
                    "extra": {
                        "finding_id": finding_id,
                        "title": title,
                        "scanner": scanner,
                        "severity": severity,
                        "status": status_val,
                        "ticket": ticket,
                        "first_detected": first_detected,
                        "date_only": date_only,
                        "host_ip": host_ip,
                    },
                })

        return records
