
from pathlib import Path
from typing import Any

from scapy.all import IP, IPv6, TCP, UDP, ICMP, PcapReader

from app.parsers.base_parser import BaseParser


class PCAPParser(BaseParser):
    """Extract network-flow metadata without processing payloads."""

    def parse(self, file_path: Path,original_filename: str | None = None,) -> list[dict[str, Any]]:
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

                timestamp = float(packet.time)
                packet_bytes = len(packet)

                source_endpoint = (source_ip, source_port)
                destination_endpoint = (
                    destination_ip,
                    destination_port,
                )

                # Sort endpoints so both directions share one flow.
                endpoints = tuple(
                    sorted(
                        (source_endpoint, destination_endpoint),
                        key=lambda endpoint: (
                            endpoint[0] or "",
                            endpoint[1] or 0,
                        ),
                    )
                )

                flow_key = (protocol, endpoints)

                if flow_key not in flows:
                    flows[flow_key] = {
                        "event_type": "network_connection",
                        "source": "pcap",
                        "source_ip": source_ip,
                        "destination_ip": destination_ip,
                        "source_port": source_port,
                        "destination_port": destination_port,
                        "protocol": protocol,
                        "bytes": 0,
                        "packets": 0,
                        "first_timestamp": timestamp,
                        "last_timestamp": timestamp,
                    }

                flow = flows[flow_key]
                flow["bytes"] += packet_bytes
                flow["packets"] += 1
                flow["first_timestamp"] = min(
                    flow["first_timestamp"], timestamp
                )
                flow["last_timestamp"] = max(
                    flow["last_timestamp"], timestamp
                )

        return list(flows.values())
