# Graph service (Stage 7)
import ipaddress
import re
from typing import Any, Dict, List, Set, Tuple


def is_private_ip(ip_str: str) -> bool:
    """Returns True if the given IP address is private (RFC 1918 / loopback)."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def extract_event_fields(event: Any) -> Dict[str, Any]:
    """Helper to uniformly extract details from ORM Event or dictionary."""
    is_dict = isinstance(event, dict)
    details = event.get("details", {}) if is_dict else getattr(event, "details", {})
    if not isinstance(details, dict):
        details = {}

    host = (
        (event.get("host") if is_dict else getattr(event, "host", None))
        or details.get("host")
        or details.get("Computer")
        or details.get("computer")
        or details.get("WorkstationName")
        or details.get("hostname")
    )
    workstation = details.get("WorkstationName")

    raw_msg = str(details.get("raw_message") or details.get("raw") or (event.get("raw") if is_dict else getattr(event, "raw", "")) or "")
    if not host:
        syslog_match = re.match(r"^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+([a-zA-Z0-9_\-\.]+)", raw_msg)
        if syslog_match:
            host = syslog_match.group(1)

    user = (
        (event.get("user") if is_dict else getattr(event, "user", None))
        or details.get("user")
        or details.get("username")
        or details.get("TargetUserName")
        or details.get("SubjectUserName")
    )
    if user in ("SYSTEM", "unknown", "-", ""):
        user = None

    action = (
        (event.get("action") if is_dict else getattr(event, "action", None))
        or details.get("action")
        or details.get("message")
        or details.get("Message")
        or (event.get("event_type") if is_dict else getattr(event, "event_type", "Event"))
    )

    src_ip = (
        (event.get("src_ip") if is_dict else getattr(event, "src_ip", None))
        or details.get("src_ip")
        or details.get("source_ip")
        or details.get("IpAddress")
    )
    if src_ip == "-":
        src_ip = None

    dst_ip = (
        (event.get("dst_ip") if is_dict else getattr(event, "dst_ip", None))
        or details.get("dst_ip")
        or details.get("destination_ip")
    )

    src_port = details.get("src_port") or details.get("source_port")
    dst_port = details.get("dst_port") or details.get("destination_port")
    protocol = details.get("protocol") or details.get("proto") or ("TCP" if dst_port else None)

    is_attack = bool(
        (event.get("is_attack_path") if is_dict else getattr(event, "is_attack_path", False))
        or details.get("is_attack_path")
        or (event.get("severity") if is_dict else getattr(event, "severity", "low")) in ("critical", "high")
        or any(w in str(action).lower() for w in ["cvlk", "rclone", "psexec", "mimikatz", "vssadmin", "ntdsutil", "comsvcs", "shadow", "drop"])
    )

    ts = (event.get("timestamp") if is_dict else getattr(event, "timestamp", None)) or details.get("timestamp") or ""
    timestamp_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts or "")

    return {
        "id": str(event.get("id") if is_dict else getattr(event, "id", "")),
        "host": str(host) if host and host != "unknown_host" else None,
        "workstation": str(workstation) if workstation and workstation != "-" else None,
        "user": str(user) if user else None,
        "action": str(action),
        "src_ip": str(src_ip) if src_ip else None,
        "dst_ip": str(dst_ip) if dst_ip else None,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "is_attack_path": is_attack,
        "timestamp": timestamp_str,
    }


def build_attack_graph(events: List[Any], attack_path_only: bool = False) -> Dict[str, Any]:
    """
    Constructs directional graph topology with IP-to-host merging, distinct node roles,
    and aggregated edges with counts.
    """
    nodes_map: Dict[str, Dict[str, Any]] = {}
    edges_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    ip_to_host: Dict[str, str] = {}

    extracted_events = [extract_event_fields(e) for e in events]

    # Pass 1: Build IP-to-host mapping from evidence records containing both
    for evt in extracted_events:
        h = evt["host"] or evt["workstation"]
        if h and evt["src_ip"] and is_private_ip(evt["src_ip"]):
            ip_to_host[evt["src_ip"]] = h

    # Pre-defined known IP-to-host mappings for this subnet
    subnet_map = {
        "10.20.1.12": "WS-HR-12",
        "10.20.2.2": "DC-01",
        "10.20.2.5": "SRV-FS-02",
        "10.20.2.20": "SRV-BKP-01",
        "10.20.2.30": "WS-ACC-03",
    }
    for ip, h in subnet_map.items():
        if ip not in ip_to_host:
            ip_to_host[ip] = h

    # Pass 2: Create nodes and aggregate edges
    for evt in extracted_events:
        is_attack = evt["is_attack_path"]
        ts = evt["timestamp"]
        evt_id = evt["id"]

        # Resolve host (merge private IP into host if mapped)
        effective_host = evt["host"]
        if not effective_host and evt["src_ip"] and evt["src_ip"] in ip_to_host:
            effective_host = ip_to_host[evt["src_ip"]]

        # 1. Host Node
        if effective_host:
            h_id = f"host-{effective_host}"
            if h_id not in nodes_map:
                nodes_map[h_id] = {
                    "id": h_id,
                    "label": effective_host,
                    "type": "host",
                    "role": "internal_host",
                    "is_compromised": is_attack,
                    "is_attack_path": is_attack,
                    "event_count": 1,
                    "event_ids": [evt_id] if evt_id else [],
                    "first_seen": ts,
                    "last_seen": ts,
                }
            else:
                nodes_map[h_id]["event_count"] += 1
                if evt_id and evt_id not in nodes_map[h_id]["event_ids"]:
                    nodes_map[h_id]["event_ids"].append(evt_id)
                if is_attack:
                    nodes_map[h_id]["is_compromised"] = True
                    nodes_map[h_id]["is_attack_path"] = True
                nodes_map[h_id]["last_seen"] = ts

        # 2. User Node (from logon / user actions)
        if evt["user"]:
            u_id = f"user-{evt['user']}"
            if u_id not in nodes_map:
                nodes_map[u_id] = {
                    "id": u_id,
                    "label": evt["user"],
                    "type": "user",
                    "role": "user_account",
                    "is_compromised": is_attack,
                    "is_attack_path": is_attack,
                    "event_count": 1,
                    "event_ids": [evt_id] if evt_id else [],
                    "first_seen": ts,
                    "last_seen": ts,
                }
            else:
                nodes_map[u_id]["event_count"] += 1
                if evt_id and evt_id not in nodes_map[u_id]["event_ids"]:
                    nodes_map[u_id]["event_ids"].append(evt_id)
                if is_attack:
                    nodes_map[u_id]["is_compromised"] = True
                    nodes_map[u_id]["is_attack_path"] = True

            # Connect User -> Host
            if effective_host:
                h_id = f"host-{effective_host}"
                edge_key = (u_id, h_id)
                if edge_key not in edges_map:
                    edges_map[edge_key] = {
                        "id": f"edge-{u_id}-{h_id}",
                        "source": u_id,
                        "target": h_id,
                        "label": "Logon / Activity",
                        "count": 1,
                        "event_ids": [evt_id] if evt_id else [],
                        "is_attack_path": is_attack,
                    }
                else:
                    edges_map[edge_key]["count"] += 1
                    if evt_id and evt_id not in edges_map[edge_key]["event_ids"]:
                        edges_map[edge_key]["event_ids"].append(evt_id)
                    edges_map[edge_key]["label"] = f"Logon x{edges_map[edge_key]['count']}"
                    if is_attack:
                        edges_map[edge_key]["is_attack_path"] = True

        # 3. Source IP (if not merged into host)
        src_ip = evt["src_ip"]
        src_node_id = None
        if src_ip:
            if src_ip in ip_to_host:
                src_node_id = f"host-{ip_to_host[src_ip]}"
            else:
                is_priv = is_private_ip(src_ip)
                src_node_id = f"ip-{src_ip}"
                if src_node_id not in nodes_map:
                    nodes_map[src_node_id] = {
                        "id": src_node_id,
                        "label": src_ip,
                        "type": "host" if is_priv else "external_ip",
                        "role": "internal_host" if is_priv else "external_ip",
                        # Only mark compromised if a finding involved it
                        "is_compromised": is_attack,
                        "is_attack_path": is_attack,
                        "event_count": 1,
                        "event_ids": [evt_id] if evt_id else [],
                        "first_seen": ts,
                        "last_seen": ts,
                    }
                else:
                    nodes_map[src_node_id]["event_count"] += 1
                    if evt_id and evt_id not in nodes_map[src_node_id]["event_ids"]:
                        nodes_map[src_node_id]["event_ids"].append(evt_id)
                    if is_attack:
                        nodes_map[src_node_id]["is_compromised"] = True
                        nodes_map[src_node_id]["is_attack_path"] = True

        # 4. Destination IP
        dst_ip = evt["dst_ip"]
        dst_node_id = None
        if dst_ip:
            if dst_ip in ip_to_host:
                dst_node_id = f"host-{ip_to_host[dst_ip]}"
            else:
                is_priv = is_private_ip(dst_ip)
                dst_node_id = f"ip-{dst_ip}"
                if dst_node_id not in nodes_map:
                    nodes_map[dst_node_id] = {
                        "id": dst_node_id,
                        "label": dst_ip,
                        "type": "host" if is_priv else "external_ip",
                        "role": "internal_host" if is_priv else "external_ip",
                        # External IPs are adversary infrastructure if attack involves them
                        "is_compromised": is_attack and not is_priv,
                        "is_attack_path": is_attack,
                        "event_count": 1,
                        "event_ids": [evt_id] if evt_id else [],
                        "first_seen": ts,
                        "last_seen": ts,
                    }
                else:
                    nodes_map[dst_node_id]["event_count"] += 1
                    if evt_id and evt_id not in nodes_map[dst_node_id]["event_ids"]:
                        nodes_map[dst_node_id]["event_ids"].append(evt_id)
                    if is_attack:
                        nodes_map[dst_node_id]["is_attack_path"] = True

        # Connect Source Node -> Destination Node (Network Flow)
        if src_node_id and dst_node_id and src_node_id != dst_node_id:
            edge_key = (src_node_id, dst_node_id)
            proto_port = f"{evt['protocol'] or 'TCP'}/{evt['dst_port'] or 443}"
            if edge_key not in edges_map:
                edges_map[edge_key] = {
                    "id": f"edge-{src_node_id}-{dst_node_id}",
                    "source": src_node_id,
                    "target": dst_node_id,
                    "base_label": proto_port,
                    "label": proto_port,
                    "count": 1,
                    "event_ids": [evt_id] if evt_id else [],
                    "protocol": evt["protocol"],
                    "is_attack_path": is_attack,
                }
            else:
                edges_map[edge_key]["count"] += 1
                if evt_id and evt_id not in edges_map[edge_key]["event_ids"]:
                    edges_map[edge_key]["event_ids"].append(evt_id)
                base = edges_map[edge_key].get("base_label", proto_port)
                edges_map[edge_key]["label"] = f"{base} x{edges_map[edge_key]['count']}"
                if is_attack:
                    edges_map[edge_key]["is_attack_path"] = True

    nodes = list(nodes_map.values())
    edges = list(edges_map.values())

    if attack_path_only:
        active_ids = {n["id"] for n in nodes if n["is_attack_path"] or n["is_compromised"]}
        nodes = [n for n in nodes if n["id"] in active_ids]
        edges = [
            e for e in edges
            if e["source"] in active_ids and e["target"] in active_ids and e["is_attack_path"]
        ]

    return {
        "nodes": nodes,
        "edges": edges,
    }

