from datetime import datetime, timezone
import os
from pathlib import Path
import re
from typing import Any

try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, Raw, PcapReader
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False
    IP = IPv6 = TCP = UDP = ICMP = DNS = Raw = PcapReader = None

from app.core.config import settings
from app.parsers.base_parser import BaseParser

_PAYLOAD_PREVIEW_LIMIT = 200
_HTTP_REQUEST_RE = re.compile(
    rb"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\r\n\s]+)\s+HTTP/(\d\.\d)"
)
_HTTP_STATUS_RE = re.compile(rb"HTTP/\d\.\d\s+(\d{3}(?:\s+[^\r\n]{1,40})?)")


def _packet_events_enabled() -> bool:
    """Return True when legacy per-packet PCAP mode is explicitly enabled."""
    env_val = os.getenv("PCAP_PACKET_EVENTS")
    if env_val is not None:
        return env_val.strip().lower() in ("1", "true", "yes", "on")
    return bool(getattr(settings, "PCAP_PACKET_EVENTS", False))


def _sanitize_payload_preview(raw_bytes: bytes, limit: int = _PAYLOAD_PREVIEW_LIMIT) -> str:
    """Return up to `limit` sanitized printable ASCII payload characters."""
    if not raw_bytes:
        return ""
    text = raw_bytes.decode("utf-8", errors="ignore")
    cleaned = []
    for ch in text:
        code = ord(ch)
        if ch in ("\r", "\n", "\t"):
            cleaned.append(" ")
        elif 0x20 <= code <= 0x7E:
            cleaned.append(ch)
    normalized = re.sub(r" {2,}", " ", "".join(cleaned)).strip()
    return normalized[:limit]


def _extract_http_summary(payload: bytes) -> tuple[str | None, str | None]:
    """Extract first cleartext HTTP request line and status string from flow bytes."""
    if not payload:
        return None, None
    req_line = None
    status_line = None
    req_match = _HTTP_REQUEST_RE.search(payload)
    if req_match:
        method = req_match.group(1).decode("ascii", errors="ignore")
        target = req_match.group(2).decode("ascii", errors="ignore")
        ver = req_match.group(3).decode("ascii", errors="ignore")
        req_line = f"{method} {target} HTTP/{ver}"
    status_match = _HTTP_STATUS_RE.search(payload)
    if status_match:
        status_line = status_match.group(1).decode("ascii", errors="ignore").strip()
    return req_line, status_line


def _extract_dns_details(packet: Any) -> tuple[str | None, list[str]]:
    """Extract DNS query name and answer records from a Scapy packet."""
    query_name = None
    query_results: list[str] = []
    if DNS not in packet:
        return query_name, query_results
    try:
        if packet[DNS].qd:
            raw_q = packet[DNS].qd.qname
            query_name = (
                raw_q.decode("utf-8", errors="ignore").rstrip(".")
                if hasattr(raw_q, "decode")
                else str(raw_q).rstrip(".")
            )
    except Exception:
        pass
    try:
        if packet[DNS].an:
            an = packet[DNS].an
            while an:
                if hasattr(an, "rdata"):
                    query_results.append(str(an.rdata))
                an = an.payload if hasattr(an, "payload") else None
    except Exception:
        pass
    return query_name, query_results


def _extract_packet_tuple(packet: Any) -> tuple[str, str, int | None, int | None, str] | None:
    """Extract (src_ip, dst_ip, src_port, dst_port, protocol) if IP/IPv6 is present."""
    source_ip = None
    destination_ip = None
    source_port = None
    destination_port = None
    protocol = "OTHER"

    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst

    if not source_ip or not destination_ip:
        return None

    if TCP in packet:
        protocol = "TCP"
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)
    elif UDP in packet:
        protocol = "UDP"
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)
    elif ICMP in packet:
        protocol = "ICMP"

    return source_ip, destination_ip, source_port, destination_port, protocol


class PCAPParser(BaseParser):
    """Extract TCP/UDP flow summaries (or individual packets when PCAP_PACKET_EVENTS=true)."""

    def _parse_packet_events(self, file_path: Path, filename: str) -> list[dict[str, Any]]:
        events = []
        seen_fingerprints = set()

        with PcapReader(str(file_path)) as reader:
            for packet_number, packet in enumerate(reader, start=1):
                parsed = _extract_packet_tuple(packet)
                if not parsed:
                    continue
                source_ip, destination_ip, source_port, destination_port, protocol = parsed

                packet_bytes = len(packet)
                pkt_ts = float(packet.time)
                timestamp_str = datetime.fromtimestamp(pkt_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                query_name, query_results = _extract_dns_details(packet)
                event_type = "dns_query" if DNS in packet else "network_connection"

                fingerprint = (filename, packet_number)
                if fingerprint in seen_fingerprints:
                    continue
                seen_fingerprints.add(fingerprint)

                if query_name:
                    res_str = f" -> {', '.join(query_results)}" if query_results else ""
                    action = f"DNS query {query_name}{res_str}"
                else:
                    action = f"{protocol} {source_ip}:{source_port or 0} -> {destination_ip}:{destination_port or 0} ({packet_bytes} B)"

                extra: dict[str, Any] = {
                    "packet_number": packet_number,
                    "bytes": packet_bytes,
                }
                if query_name:
                    extra["query_name"] = query_name
                    extra["query_results"] = query_results

                events.append({
                    "timestamp": timestamp_str,
                    "first_timestamp": pkt_ts,
                    "last_timestamp": pkt_ts,
                    "host": source_ip,
                    "host_inferred": True,
                    "source_file": filename,
                    "source_record_id": packet_number,
                    "event_type": event_type,
                    "event_id": None,
                    "user": None,
                    "process": None,
                    "parent_process": None,
                    "command_line": query_name or action,
                    "src_ip": source_ip,
                    "dst_ip": destination_ip,
                    "src_port": source_port,
                    "dst_port": destination_port,
                    "protocol": protocol,
                    "bytes": packet_bytes,
                    "service_name": None,
                    "target_file": query_name,
                    "raw": action,
                    "action": action,
                    "extra": extra,
                })

        return events

    def _parse_flow_events(self, file_path: Path, filename: str) -> list[dict[str, Any]]:
        flows: dict[tuple[Any, ...], dict[str, Any]] = {}

        with PcapReader(str(file_path)) as reader:
            for packet_number, packet in enumerate(reader, start=1):
                parsed = _extract_packet_tuple(packet)
                if not parsed:
                    continue
                source_ip, destination_ip, source_port, destination_port, protocol = parsed

                if protocol in ("TCP", "UDP"):
                    ep1 = (source_ip, source_port or 0)
                    ep2 = (destination_ip, destination_port or 0)
                    flow_key: tuple[Any, ...] = (protocol, min(ep1, ep2), max(ep1, ep2))
                else:
                    flow_key = (protocol, min(source_ip, destination_ip), max(source_ip, destination_ip))

                pkt_ts = float(packet.time)
                pkt_bytes = len(packet)

                flow = flows.get(flow_key)
                if flow is None:
                    flow = {
                        "first_packet_number": packet_number,
                        "first_timestamp": pkt_ts,
                        "last_timestamp": pkt_ts,
                        "src_ip": source_ip,
                        "dst_ip": destination_ip,
                        "src_port": source_port,
                        "dst_port": destination_port,
                        "protocol": protocol,
                        "packets": 0,
                        "bytes": 0,
                        "flags": set(),
                        "payload_chunks": [],
                        "is_dns": False,
                        "query_name": None,
                        "query_results": [],
                    }
                    flows[flow_key] = flow
                else:
                    if pkt_ts < flow["first_timestamp"]:
                        flow["first_timestamp"] = pkt_ts
                    if pkt_ts > flow["last_timestamp"]:
                        flow["last_timestamp"] = pkt_ts

                flow["packets"] += 1
                flow["bytes"] += pkt_bytes

                if TCP in packet:
                    flow["flags"].update(str(packet[TCP].flags))

                if DNS in packet:
                    flow["is_dns"] = True
                    q_name, q_res = _extract_dns_details(packet)
                    if q_name and not flow["query_name"]:
                        flow["query_name"] = q_name
                    for ans in q_res:
                        if ans not in flow["query_results"]:
                            flow["query_results"].append(ans)

                if Raw in packet and packet[Raw].load:
                    flow["payload_chunks"].append(bytes(packet[Raw].load))

        events: list[dict[str, Any]] = []
        for flow in flows.values():
            first_ts = flow["first_timestamp"]
            last_ts = flow["last_timestamp"]
            first_dt = datetime.fromtimestamp(first_ts, tz=timezone.utc)
            last_dt = datetime.fromtimestamp(last_ts, tz=timezone.utc)
            timestamp_str = first_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            last_time_str = last_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

            payload_bytes = b"".join(flow["payload_chunks"])
            http_request, http_status = _extract_http_summary(payload_bytes)
            payload_preview = _sanitize_payload_preview(payload_bytes)

            protocol = flow["protocol"]
            src_ip = flow["src_ip"]
            dst_ip = flow["dst_ip"]
            src_port = flow["src_port"]
            dst_port = flow["dst_port"]
            packets = flow["packets"]
            total_bytes = flow["bytes"]
            flags_str = "".join(sorted(flow["flags"])) if flow["flags"] else None

            event_type = "dns_query" if flow["is_dns"] else "network_connection"

            if flow["query_name"]:
                res_str = f" -> {', '.join(flow['query_results'])}" if flow["query_results"] else ""
                summary = f"DNS query {flow['query_name']}{res_str} ({packets} pkts, {total_bytes} B)"
            elif http_request:
                status_part = f" -> {http_status}" if http_status else ""
                summary = (
                    f"HTTP {src_ip}:{src_port or 0} -> {dst_ip}:{dst_port or 0} "
                    f"{http_request}{status_part} ({packets} pkts, {total_bytes} B)"
                )
            else:
                flags_part = f" [{flags_str}]" if flags_str else ""
                summary = (
                    f"{protocol} {src_ip}:{src_port or 0} -> {dst_ip}:{dst_port or 0}"
                    f"{flags_part} ({packets} pkts, {total_bytes} B)"
                )

            action = summary[:160]
            raw_lines = [
                f"{summary} | window {timestamp_str}..{last_time_str}"
            ]
            if http_request:
                raw_lines.append(f"HTTP Request: {http_request}" + (f" | Status: {http_status}" if http_status else ""))
            if payload_preview:
                raw_lines.append(f"[UNTRUSTED PAYLOAD] {payload_preview}")
            raw_text = "\n".join(raw_lines)

            extra: dict[str, Any] = {
                "packet_number": flow["first_packet_number"],
                "first_timestamp": first_ts,
                "last_timestamp": last_ts,
                "packets": packets,
                "bytes": total_bytes,
                "payload_untrusted": True,
            }
            if flags_str:
                extra["flags"] = flags_str
            if http_request:
                extra["http_request"] = http_request
            if http_status:
                extra["http_status"] = http_status
            if payload_preview:
                extra["payload_preview"] = payload_preview
            if flow["query_name"]:
                extra["query_name"] = flow["query_name"]
                extra["query_results"] = flow["query_results"]

            events.append({
                "timestamp": timestamp_str,
                "first_timestamp": first_ts,
                "last_timestamp": last_ts,
                "host": src_ip,
                "host_inferred": True,
                "source_file": filename,
                "source_record_id": flow["first_packet_number"],
                "event_type": event_type,
                "event_id": None,
                "user": None,
                "process": None,
                "parent_process": None,
                "command_line": flow["query_name"] or action,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "packets": packets,
                "bytes": total_bytes,
                "flags": flags_str,
                "http_request": http_request,
                "http_status": http_status,
                "payload_preview": payload_preview or None,
                "payload_untrusted": True,
                "service_name": None,
                "target_file": flow["query_name"],
                "raw": raw_text,
                "action": action,
                "extra": extra,
            })

        return events

    def parse(self, file_path: Path, original_filename: str | None = None) -> list[dict[str, Any]]:
        filename = original_filename or file_path.name

        if not HAVE_SCAPY:
            raise RuntimeError("scapy is required for PCAP packet parsing. Please install scapy.")

        if _packet_events_enabled():
            return self._parse_packet_events(file_path, filename)
        return self._parse_flow_events(file_path, filename)

