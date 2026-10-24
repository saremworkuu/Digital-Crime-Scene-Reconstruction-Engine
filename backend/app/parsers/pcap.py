from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, PcapReader
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False
    IP = IPv6 = TCP = UDP = ICMP = DNS = PcapReader = None

from app.parsers.base_parser import BaseParser


class PCAPParser(BaseParser):
    """Extract individual network packet events with DNS and protocol metadata."""

    def parse(self, file_path: Path, original_filename: str | None = None) -> list[dict[str, Any]]:
        filename = original_filename or file_path.name

        if not HAVE_SCAPY:
            raise RuntimeError("scapy is required for PCAP packet parsing. Please install scapy.")

        events = []
        with PcapReader(str(file_path)) as reader:
            for packet_number, packet in enumerate(reader, start=1):
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
                    continue

                if TCP in packet:
                    protocol = "TCP"
                    source_port = packet[TCP].sport
                    destination_port = packet[TCP].dport
                elif UDP in packet:
                    protocol = "UDP"
                    source_port = packet[UDP].sport
                    destination_port = packet[UDP].dport
                elif ICMP in packet:
                    protocol = "ICMP"

                packet_bytes = len(packet)
                dt = datetime.fromtimestamp(float(packet.time), tz=timezone.utc)
                timestamp_str = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

                query_name = None
                query_results = []
                event_type = "network_connection"

                if DNS in packet:
                    event_type = "dns_query"
                    try:
                        if packet[DNS].qd:
                            raw_q = packet[DNS].qd.qname
                            query_name = raw_q.decode("utf-8", errors="ignore").rstrip(".") if hasattr(raw_q, "decode") else str(raw_q).rstrip(".")
                    except Exception:
                        pass
                    try:
                        if packet[DNS].an:
                            # Answers
                            an = packet[DNS].an
                            while an:
                                if hasattr(an, "rdata"):
                                    query_results.append(str(an.rdata))
                                an = an.payload if hasattr(an, "payload") else None
                    except Exception:
                        pass

                # Action summary
                if query_name:
                    res_str = f" -> {', '.join(query_results)}" if query_results else ""
                    action = f"DNS query {query_name}{res_str}"
                else:
                    action = f"{protocol} {source_ip}:{source_port or 0} -> {destination_ip}:{destination_port or 0} ({packet_bytes} B)"

                extra = {
                    "packet_number": packet_number,
                    "bytes": packet_bytes,
                }
                if query_name:
                    extra["query_name"] = query_name
                    extra["query_results"] = query_results

                events.append({
                    "timestamp": timestamp_str,
                    "first_timestamp": float(packet.time),
                    "last_timestamp": float(packet.time),
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

