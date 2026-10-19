
# Tests for the PCAP connection-summary parser

import tempfile
from pathlib import Path

from scapy.all import IP, TCP, UDP, Ether, wrpcap

from app.parsers.pcap import PCAPParser


parser = PCAPParser()

with tempfile.TemporaryDirectory() as temp_dir:
    folder = Path(temp_dir)
    pcap_file = folder / "sample.pcap"

    # TCP packet: client -> server
    tcp_packet_1 = (
        Ether(
            src="02:00:00:00:00:01",
            dst="02:00:00:00:00:02",
        )
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=12345, dport=80)
    )
    tcp_packet_1.time = 1000.0

    # TCP packet: server -> client (same flow, reverse direction)
    tcp_packet_2 = (
        Ether(
            src="02:00:00:00:00:02",
            dst="02:00:00:00:00:01"
        )
        / IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=80, dport=12345)
    )
    tcp_packet_2.time = 1002.0

    # Separate UDP flow
    udp_packet = (
        Ether(
            src="02:00:00:00:00:02", dst="02:00:00:00:00:01"
        )
        / IP(src="192.168.1.30", dst="192.168.1.40")
        / UDP(sport=5353, dport=53)
    )
    udp_packet.time = 1001.0

    wrpcap(
        str(pcap_file),
        [tcp_packet_1, tcp_packet_2, udp_packet],
    )

    records = parser.parse(pcap_file)

    # Three packets should produce two flows.
    assert len(records) == 2

    tcp_flow = next(
        record for record in records
        if record["protocol"] == "TCP"
    )
    udp_flow = next(
        record for record in records
        if record["protocol"] == "UDP"
    )

    # Verify TCP flow summary.
    assert tcp_flow["event_type"] == "network_connection"
    assert tcp_flow["packets"] == 2
    assert tcp_flow["bytes"] == (
        len(tcp_packet_1) + len(tcp_packet_2)
    )
    assert tcp_flow["first_timestamp"] == 1000.0
    assert tcp_flow["last_timestamp"] == 1002.0
    assert {
        tcp_flow["source_ip"],
        tcp_flow["destination_ip"],
    } == {"192.168.1.10", "192.168.1.20"}

    # Verify UDP flow summary.
    assert udp_flow["packets"] == 1
    assert udp_flow["bytes"] == len(udp_packet)
    assert udp_flow["source_ip"] == "192.168.1.30"
    assert udp_flow["destination_ip"] == "192.168.1.40"
    assert udp_flow["source_port"] == 5353
    assert udp_flow["destination_port"] == 53
    assert udp_flow["first_timestamp"] == 1001.0
    assert udp_flow["last_timestamp"] == 1001.0

    print("PCAP connection-summary tests passed!")

print("All PCAP parser tests passed!")
