import csv
import json
from pathlib import Path
from typing import Any
from app.parsers.base_parser import BaseParser


class GenericCSVJSONParser(BaseParser):
    
    def parse(
        self,
        file_path: Path,
        original_filename: str | None = None,
    ) -> list[dict[str, Any]]:
        filename = original_filename or file_path.name
        extension = (
            Path(original_filename).suffix.lower()
            if original_filename
            else file_path.suffix.lower()
        )

        if extension == ".csv":
            return self._parse_csv(file_path, filename)

        if extension == ".json":
            return self._parse_json(file_path, filename)

        if extension in {".log", ".txt"}:
            with file_path.open(
                "r", encoding="utf-8-sig", errors="replace"
            ) as file:
                first_char = ""
                while True:
                    char = file.read(1)
                    if not char or not char.isspace():
                        first_char = char
                        break

            if first_char in {"{", "["}:
                return self._parse_json(file_path, filename)

            from app.parsers.txt_parser import TextFileParser
            return TextFileParser().parse(file_path, original_filename=filename)

        raise ValueError(f"Unsupported file extension or content: {extension}")

    def _detect_csv_type(self, headers: list[str]) -> str:
        """Detect CSV type from headers: network flow, metrics, or generic."""
        headers_lower = [h.lower() for h in headers]
        
        # Check for network flow: src/dst IP and ports
        network_indicators = ["src_ip", "source_ip", "dst_ip", "destination_ip", "src_port", "source_port", "dst_port", "destination_port"]
        network_count = sum(1 for h in headers_lower if any(ind in h for ind in network_indicators))
        if network_count >= 2:
            return "network_connection"
        
        # Check for time series metrics: cpu, mem, net columns
        metrics_indicators = ["cpu", "memory", "mem", "net", "network", "bytes_in", "bytes_out", "load"]
        metrics_count = sum(1 for h in headers_lower if any(ind in h for ind in metrics_indicators))
        if metrics_count >= 2:
            return "metric"
        
        # Default to generic
        return "csv_record"

    def _parse_csv(self, file_path: Path, filename: str) -> list[dict[str, Any]]:
        events = []
        with file_path.open("r", encoding="utf-8-sig", newline="") as file:
            reader = csv.DictReader(file)
            # Detect CSV type from headers
            csv_type = self._detect_csv_type(reader.fieldnames or [])
            
            for row_idx, row in enumerate(reader, start=1):
                d = dict(row)
                ts = (
                    d.get("timestamp_utc")
                    or d.get("timestamp")
                    or d.get("time")
                    or d.get("date")
                    or d.get("Time")
                )
                src_ip = d.get("src_ip") or d.get("source_ip") or d.get("SourceIp")
                dst_ip = d.get("dst_ip") or d.get("destination_ip") or d.get("DestinationIp")
                
                src_port = d.get("src_port") or d.get("source_port")
                src_port_int = int(src_port) if src_port and str(src_port).isdigit() else None

                dst_port = d.get("dst_port") or d.get("destination_port")
                dst_port_int = int(dst_port) if dst_port and str(dst_port).isdigit() else None

                proto = d.get("proto") or d.get("protocol") or ("TCP" if dst_port_int else None)
                bytes_val = None
                if d.get("bytes_out") or d.get("bytes_in"):
                    try:
                        bytes_val = int(d.get("bytes_out", 0) or 0) + int(d.get("bytes_in", 0) or 0)
                    except Exception:
                        pass
                elif d.get("bytes") and str(d["bytes"]).isdigit():
                    bytes_val = int(d["bytes"])

                host = d.get("host") or d.get("computer") or src_ip or "unknown_host"
                host_inferred = False if d.get("host") or d.get("computer") else True

                # Build action based on CSV type
                if csv_type == "metric":
                    cpu_val = d.get("cpu") or d.get("cpu_percent") or d.get("cpu_usage")
                    mem_val = d.get("memory") or d.get("mem") or d.get("memory_percent") or d.get("mem_usage")
                    summary_parts = []
                    if cpu_val:
                        summary_parts.append(f"CPU {cpu_val}%")
                    if mem_val:
                        summary_parts.append(f"MEM {mem_val}%")
                    action_val = ", ".join(summary_parts) if summary_parts else f"Metrics for {host}"
                elif csv_type == "network_connection":
                    action_val = d.get("action") or f"{proto or 'IP'} {src_ip or ''}:{src_port or ''} -> {dst_ip or ''}:{dst_port or ''}"
                else:
                    # Generic: show key columns
                    key_vals = []
                    for key in ["host", "user", "action", "status", "event_type"]:
                        if d.get(key):
                            key_vals.append(f"{key}={d[key]}")
                    action_val = ", ".join(key_vals) if key_vals else "CSV record"

                events.append({
                    **d,
                    "timestamp": ts,
                    "host": host,
                    "host_inferred": host_inferred,
                    "source_file": filename,
                    "source_record_id": row_idx,
                    "event_type": csv_type,
                    "event_id": d.get("event_id"),
                    "user": d.get("user") or d.get("username"),
                    "process": d.get("process") or d.get("image"),
                    "parent_process": d.get("parent_process"),
                    "command_line": d.get("command_line"),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port_int,
                    "dst_port": dst_port_int,
                    "protocol": proto,
                    "bytes": bytes_val,
                    "service_name": d.get("service") or d.get("service_name"),
                    "target_file": d.get("target_file") or d.get("path"),
                    "raw": str(d),
                    "action": action_val,
                    "extra": d,
                })
        return events

    def _parse_json(self, file_path: Path, filename: str) -> list[dict[str, Any]]:
        with file_path.open("r", encoding="utf-8-sig") as file:
            data = json.load(file)

        items = []
        parent_meta = {}

        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            # Check for standard nested event arrays (e.g. alerts, events, records, items)
            found_array_key = None
            for key in ("alerts", "events", "records", "items", "results"):
                if key in data and isinstance(data[key], list):
                    found_array_key = key
                    break

            if found_array_key:
                parent_meta = {k: v for k, v in data.items() if k != found_array_key}
                items = data[found_array_key]
            else:
                items = [data]
        else:
            raise ValueError("JSON must contain an object or a list of objects.")

        events = []
        for idx, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                continue

            d = {**parent_meta, **item}

            ts = (
                d.get("time")
                or d.get("timestamp")
                or d.get("TimeCreated")
                or d.get("@timestamp")
                or d.get("date")
            )
            host = d.get("host") or d.get("computer") or d.get("Computer") or d.get("hostname")
            user = d.get("user") or d.get("username") or d.get("TargetUserName")
            
            mitre_val = d.get("mitre") or d.get("mitre_technique") or d.get("technique")
            mitre_str = ", ".join(mitre_val) if isinstance(mitre_val, list) else str(mitre_val or "")

            rule_name = d.get("rule") or d.get("rule_name") or d.get("alert_name") or d.get("title")
            alert_id = d.get("id") or d.get("alert_id") or str(idx)

            action = f"EDR Alert: {rule_name} ({alert_id})" if rule_name else (d.get("action") or d.get("message") or "JSON Event")

            src_ip = d.get("src_ip") or d.get("source_ip") or d.get("SourceIp")
            dst_ip = d.get("dst_ip") or d.get("destination_ip") or d.get("DestinationIp")

            events.append({
                **d,
                "timestamp": ts,
                "host": host or src_ip or "unknown_host",
                "host_inferred": False if host else True,
                "source_file": filename,
                "source_record_id": alert_id,
                "event_type": "edr_alert" if "alerts" in str(file_path).lower() or parent_meta.get("source") == "SyntheticEDR" or "rule" in d else d.get("event_type", "json_event"),
                "event_id": alert_id,
                "user": user,
                "process": d.get("process") or d.get("Image") or d.get("image"),
                "parent_process": d.get("parent_process") or d.get("ParentImage"),
                "command_line": d.get("command_line") or d.get("CommandLine"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": int(d["src_port"]) if d.get("src_port") and str(d["src_port"]).isdigit() else None,
                "dst_port": int(d["dst_port"]) if d.get("dst_port") and str(d["dst_port"]).isdigit() else None,
                "protocol": d.get("protocol") or d.get("proto"),
                "bytes": int(d["bytes"]) if d.get("bytes") and str(d["bytes"]).isdigit() else None,
                "service_name": d.get("service") or d.get("service_name"),
                "target_file": d.get("target_file") or d.get("path"),
                "raw": json.dumps(item),
                "action": action,
                "extra": {
                    **d,
                    "rule": rule_name,
                    "mitre_technique": mitre_str,
                    "severity": d.get("severity", "medium"),
                    "source": parent_meta.get("source", "EDR"),
                },
            })

        return events

    