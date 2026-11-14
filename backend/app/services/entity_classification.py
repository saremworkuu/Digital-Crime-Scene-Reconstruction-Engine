"""Shared, evidence-led entity classification helpers."""
import ipaddress


def is_internal_ip(value: str) -> bool:
    """True for RFC1918, loopback, and link-local addresses.

    Reserved documentation ranges (for example TEST-NET addresses used in
    fixtures) remain externally classifiable indicators.
    """
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return address.is_loopback or address.is_link_local or any(
        address in ipaddress.ip_network(network)
        for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    )


def infrastructure_role(*, tactic: str = "", field_role: str = "") -> str | None:
    """Map explicit finding context to a display role; no traffic-only claims."""
    role = (field_role or "").strip().lower()
    if role in {"c2", "command_and_control", "command and control"} or tactic == "Command and Control":
        return "C2"
    if role in {"payload", "payload_source"}:
        return "Payload"
    if tactic == "Initial Access":
        return "Payload"
    if role in {"exfiltration", "exfil", "exfiltration_destination"} or tactic == "Exfiltration":
        return "Exfiltration"
    if role in {"attack_source", "source", "attacker"}:
        return "Attack Source"
    if tactic in {"Credential Access", "Reconnaissance"}:
        return "Attack Source"
    return None
