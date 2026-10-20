from pathlib import Path
from typing import Any

try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, PcapReader
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False
    IP = IPv6 = TCP = UDP = ICMP = PcapReader = None

from app.parsers.base_parser import BaseParser


class PCAPParser(BaseParser):
    """Extract network-flow metadata without processing payloads."""

    def parse(self, file_path: Path, original_filename: str | None = None) -> list[dict[str, Any]]:
        if not HAVE_SCAPY:
            raise RuntimeError("scapy is required for PCAP packet parsing. Please install scapy.")

        flows: dict[tuple, dict[str, Any]] = {}

        with PcapReader(str(file_path)) as packets:
            for packet in packets:
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

                timestamp = float(packet.time)
                packet_bytes = len(packet)

                flow_key = (
                    source_ip,
                    destination_ip,
                    source_port,
                    destination_port,
                    protocol,
                )

                if flow_key not in flows:
                    flows[flow_key] = {
                        "event_type": "network_connection",
                        "source": "pcap",
                        "first_timestamp": timestamp,
                        "last_timestamp": timestamp,
                        "source_ip": source_ip,
                        "destination_ip": destination_ip,
                        "source_port": source_port,
                        "destination_port": destination_port,
                        "protocol": protocol,
                        "packets": 1,
                        "bytes": packet_bytes,
                    }
                else:
                    flow = flows[flow_key]
                    flow["last_timestamp"] = timestamp
                    flow["packets"] += 1
                    flow["bytes"] += packet_bytes

        return list(flows.values())
