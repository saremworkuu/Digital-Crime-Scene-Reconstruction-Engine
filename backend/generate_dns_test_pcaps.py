
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, UDP, wrpcap

OUTPUT_DIR = Path("dns_test_captures")
OUTPUT_DIR.mkdir(exist_ok=True)

SOURCE_IP = "192.0.2.20"
DNS_SERVER_IP = "192.0.2.53"


def make_dns_query(query_name: str, index: int):
    """Build one synthetic DNS query packet."""

    packet = (
        IP(src=SOURCE_IP, dst=DNS_SERVER_IP)
        / UDP(sport=53000 + index, dport=53)
        / DNS(
            id=index,
            rd=1,
            qd=DNSQR(qname=query_name, qtype="TXT"),
        )
    )

    # Give packets distinct timestamps for event reconstruction.
    packet.time = 1792396800 + index * 2
    return packet


def save_both_formats(packets, base_name: str):
    """Write equivalent PCAP and PCAPNG captures."""

    pcap_path = OUTPUT_DIR / f"{base_name}.pcap"
    pcapng_path = OUTPUT_DIR / f"{base_name}.pcapng"

    # Standard PCAP.
    wrpcap(str(pcap_path), packets)

    # Scapy's PcapNgWriter writes the PCAPNG format.
    from scapy.utils import PcapNgWriter

    with PcapNgWriter(str(pcapng_path)) as writer:
        for packet in packets:
            writer.write(packet)

    print(f"Created: {pcap_path}")
    print(f"Created: {pcapng_path}")


# Capture 1: ordinary DNS requests.
normal_domains = [
    "www.example.com",
    "mail.example.com",
    "api.example.com",
    "docs.example.com",
]

normal_packets = [
    make_dns_query(domain, index + 1)
    for index, domain in enumerate(normal_domains)
]

save_both_formats(normal_packets, "normal_dns")


# Capture 2: suspicious-looking, long, unique DNS labels.
# These are synthetic test names, not real exfiltration.
suspicious_packets = []

for index in range(25):
    label = f"{index:02d}" + ("a8K3mZ7qP2vN9xR4" * 4)
    query_name = f"{label}.tunnel-test.example"

    suspicious_packets.append(
        make_dns_query(query_name, index + 101)
    )

save_both_formats(suspicious_packets, "suspicious_dns")

print("\nDNS test captures generated successfully.")
