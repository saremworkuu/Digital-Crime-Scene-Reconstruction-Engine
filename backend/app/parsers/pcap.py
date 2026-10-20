
from pathlib import Path
from typing import Any

from scapy.all import (
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    DNS,
    DNSQR,
    PcapReader,
)

from app.parsers.base_parser import BaseParser


class PCAPParser(BaseParser):
    """Extract network flows and DNS metadata from packet captures."""

    def parse(
        self,
        file_path: Path,
        original_filename: str | None = None,
    ) -> list[dict[str, Any]]:
        flows: dict[tuple, dict[str, Any]] = {}
        dns_events: list[dict[str, Any]] = []

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

                # Preserve the existing bidirectional flow aggregation.
                source_endpoint = (source_ip, source_port)
                destination_endpoint = (
                    destination_ip,
                    destination_port,
                )

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

                # Extract DNS metadata separately from network flows.
                if DNS not in packet or DNSQR not in packet:
                    continue

                dns = packet[DNS]
                question = dns.qd

                if question is None:
                    continue

                raw_name = question.qname

                if isinstance(raw_name, bytes):
                    query_name = raw_name.decode(
                        "ascii", errors="replace"
                    )
                else:
                    query_name = str(raw_name)

                query_name = query_name.rstrip(".").lower()

                if not query_name:
                    continue

                # QR=0 means query; QR=1 means response.
                is_response = bool(dns.qr)

                dns_events.append({
                    "event_type": (
                        "dns_response" if is_response else "dns_query"
                    ),
                    "source": "pcap",
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "source_port": source_port,
                    "destination_port": destination_port,
                    "query_name": query_name,
                    "query_type": int(question.qtype),
                    "timestamp": timestamp,
                    "transaction_id": int(dns.id),
                })

        # Keep existing flow events and add the DNS events.
        return list(flows.values()) + dns_events
