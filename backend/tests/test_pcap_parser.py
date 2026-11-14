# Tests for the PCAP parser
import tempfile
from pathlib import Path
from scapy.all import IP, TCP, UDP, Ether, wrpcap

from app.parsers.pcap import PCAPParser


def test_pcap_parser():
    parser = PCAPParser()

    with tempfile.TemporaryDirectory() as temp_dir:
        folder = Path(temp_dir)
        pcap_file = folder / "sample.pcap"

        # TCP packet: client -> server
        tcp_packet_1 = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=12345, dport=80)
        )
        tcp_packet_1.time = 1000.0

        # TCP packet: server -> client (same flow, reverse direction)
        tcp_packet_2 = (
            Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
            / IP(src="192.168.1.20", dst="192.168.1.10")
            / TCP(sport=80, dport=12345)
        )
        tcp_packet_2.time = 1002.0

        # Separate UDP packet
        udp_packet = (
            Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
            / IP(src="192.168.1.30", dst="192.168.1.40")
            / UDP(sport=5353, dport=53)
        )
        udp_packet.time = 1001.0

        wrpcap(str(pcap_file), [tcp_packet_1, tcp_packet_2, udp_packet])

        records = parser.parse(pcap_file)

        # Three packets produce exactly three packet events (Stage 1)
        assert len(records) == 3

        tcp_records = [r for r in records if r["protocol"] == "TCP"]
        assert len(tcp_records) == 2

        udp_records = [r for r in records if r["protocol"] == "UDP"]
        assert len(udp_records) == 1
        udp_flow = udp_records[0]

        # Verify TCP packet record
        assert tcp_records[0]["event_type"] in ("network_connection", "network_packet")
        assert {tcp_records[0]["src_ip"], tcp_records[0]["dst_ip"]} == {"192.168.1.10", "192.168.1.20"}

        # Verify UDP packet record
        assert udp_flow["bytes"] == len(udp_packet)
        assert udp_flow["src_ip"] == "192.168.1.30"
        assert udp_flow["dst_ip"] == "192.168.1.40"
        assert udp_flow["src_port"] == 5353
        assert udp_flow["dst_port"] == 53
        assert udp_flow["first_timestamp"] == 1001.0
