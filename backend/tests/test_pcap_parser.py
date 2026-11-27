# Tests for the PCAP and PCAPNG parsers
import sys
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap

from app.parsers.pcap import PCAPParser
from app.parsers.pcapng import PCAPNGParser
from app.parsers.registry import get_parser
from app.services.detection_engine import execute_detections_on_events
from app.services.normalizer import normalize_records

WEB_COMPROMISE_PCAP = (
    Path(__file__).resolve().parents[1]
    / "test_evidence"
    / "web_server_compromise"
    / "09_capture_web_attack.pcap"
)
WEB_COMPROMISE_AUDITD = (
    Path(__file__).resolve().parents[1]
    / "test_evidence"
    / "web_server_compromise"
    / "03_auditd.log"
)


def _write_synthetic_pcap(path: Path) -> tuple[int, int, int]:
    """Write 2 bidirectional TCP packets + 1 UDP packet and return their byte lengths."""
    tcp_packet_1 = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=12345, dport=80, flags="S")
    )
    tcp_packet_1.time = 1000.0

    tcp_packet_2 = (
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
        / IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=80, dport=12345, flags="PA")
        / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example\r\n\r\nHTTP/1.1 200 OK\r\n\x00<script>alert(1)</script>")
    )
    tcp_packet_2.time = 1002.0

    udp_packet = (
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
        / IP(src="192.168.1.30", dst="192.168.1.40")
        / UDP(sport=5353, dport=53)
    )
    udp_packet.time = 1001.0

    wrpcap(str(path), [tcp_packet_1, tcp_packet_2, udp_packet])
    return len(tcp_packet_1), len(tcp_packet_2), len(udp_packet)


def test_pcap_flow_summary_default_and_packet_toggle(monkeypatch):
    parser = PCAPParser()

    with tempfile.TemporaryDirectory() as temp_dir:
        pcap_file = Path(temp_dir) / "sample.pcap"
        l1, l2, l3 = _write_synthetic_pcap(pcap_file)

        # Default mode: one flow summary per TCP/UDP flow
        monkeypatch.delenv("PCAP_PACKET_EVENTS", raising=False)
        flows = parser.parse(pcap_file)
        assert len(flows) == 2

        tcp_flow = next(r for r in flows if r["protocol"] == "TCP")
        udp_flow = next(r for r in flows if r["protocol"] == "UDP")

        assert tcp_flow["packets"] == 2
        assert tcp_flow["bytes"] == l1 + l2
        assert tcp_flow["first_timestamp"] == 1000.0
        assert tcp_flow["last_timestamp"] == 1002.0
        assert tcp_flow["src_ip"] == "192.168.1.10"
        assert tcp_flow["dst_ip"] == "192.168.1.20"
        assert tcp_flow["src_port"] == 12345
        assert tcp_flow["dst_port"] == 80
        assert set(tcp_flow["flags"] or "") >= {"S", "P", "A"}
        assert tcp_flow["http_request"] == "GET /index.html HTTP/1.1"
        assert tcp_flow["http_status"] == "200 OK"
        assert tcp_flow["payload_untrusted"] is True
        assert tcp_flow["payload_preview"]
        assert len(tcp_flow["payload_preview"]) <= 200
        assert "\x00" not in tcp_flow["payload_preview"]
        assert "[UNTRUSTED PAYLOAD]" in tcp_flow["raw"]

        assert udp_flow["packets"] == 1
        assert udp_flow["bytes"] == l3
        assert udp_flow["first_timestamp"] == 1001.0
        assert udp_flow["last_timestamp"] == 1001.0

        # Legacy per-packet mode via PCAP_PACKET_EVENTS=true
        monkeypatch.setenv("PCAP_PACKET_EVENTS", "true")
        packets = parser.parse(pcap_file)
        assert len(packets) == 3
        assert len([r for r in packets if r["protocol"] == "TCP"]) == 2
        assert len([r for r in packets if r["protocol"] == "UDP"]) == 1


def test_sample_web_attack_pcap_5_flows_4444_payload_and_detection(monkeypatch):
    monkeypatch.delenv("PCAP_PACKET_EVENTS", raising=False)
    assert WEB_COMPROMISE_PCAP.is_file()

    flows = PCAPParser().parse(WEB_COMPROMISE_PCAP, WEB_COMPROMISE_PCAP.name)
    assert len(flows) == 5, f"Expected 5 flow events, got {len(flows)}"

    # Legacy mode still produces the 64 packet events when toggled
    monkeypatch.setenv("PCAP_PACKET_EVENTS", "true")
    packet_events = PCAPParser().parse(WEB_COMPROMISE_PCAP, WEB_COMPROMISE_PCAP.name)
    assert len(packet_events) == 64
    monkeypatch.delenv("PCAP_PACKET_EVENTS", raising=False)

    # Cleartext HTTP flows capture request lines and status
    http_flows = [f for f in flows if f["dst_port"] == 80]
    assert len(http_flows) == 4
    assert any("GET /product.php?id=1'" in (f.get("http_request") or "") and "500" in (f.get("http_status") or "") for f in http_flows)
    assert any("POST /upload.php" in (f.get("http_request") or "") for f in http_flows)

    # Port 4444 reverse-shell flow captures packet/byte stats, flags, and untrusted payload commands
    flow_4444 = [f for f in flows if f["dst_port"] == 4444]
    assert len(flow_4444) == 1
    s4444 = flow_4444[0]
    assert s4444["packets"] == 24
    assert s4444["bytes"] == 1548
    assert set(s4444["flags"] or "") >= {"A", "F", "P", "S"}
    assert s4444["payload_untrusted"] is True
    assert s4444["payload_preview"] is not None
    assert len(s4444["payload_preview"]) <= 200
    assert "sudo -l" in s4444["payload_preview"]
    assert "sudo vim" in s4444["payload_preview"]

    # Normalized PCAP + auditd events still trigger the 4444 / reverse shell detection
    auditd_records = get_parser(WEB_COMPROMISE_AUDITD, WEB_COMPROMISE_AUDITD.name).parse(
        WEB_COMPROMISE_AUDITD, WEB_COMPROMISE_AUDITD.name
    )
    norm_events = normalize_records(flows + auditd_records)
    wrapped = [SimpleNamespace(id=f"ev-{idx}", **ev) for idx, ev in enumerate(norm_events)]
    findings = execute_detections_on_events(wrapped, uuid.uuid4())
    rev_shell = [f for f in findings if f.get("rule_id") == "rule-reverse-shell-pattern"]
    assert rev_shell, "Expected rule-reverse-shell-pattern (port 4444 reverse shell) to still fire"


def test_pcapng_inherits_flow_parser_and_missing_scapy_fallback(monkeypatch):
    import app.parsers.pcap as pcap_module
    from app.parsers.log_parser import LogFileParser

    assert issubclass(PCAPNGParser, PCAPParser)
    assert isinstance(get_parser(Path("sample.pcapng")), PCAPNGParser)

    # Missing scapy raises RuntimeError cleanly when calling PCAPParser directly
    monkeypatch.setattr(pcap_module, "HAVE_SCAPY", False)
    with pytest.raises(RuntimeError, match="scapy is required"):
        PCAPNGParser().parse(Path("sample.pcapng"))

    # Registry falls back to LogFileParser if pcap module import fails
    monkeypatch.setitem(sys.modules, "app.parsers.pcapng", None)
    assert isinstance(get_parser(Path("sample.pcapng")), LogFileParser)
