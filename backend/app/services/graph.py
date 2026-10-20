# Graph service
from typing import Any, Dict, List


def extract_event_fields(event: Any) -> Dict[str, Any]:
    """Helper to uniformly extract details from ORM Event or dictionary."""
    if isinstance(event, dict):
        details = event.get("details", {}) or {}
        # Merge top-level if present
        host = event.get("host") or details.get("host") or details.get("Computer") or details.get("WorkstationName")
        user = event.get("user") or details.get("user") or details.get("username") or details.get("TargetUserName")
        action = event.get("action") or details.get("action") or details.get("message") or details.get("Message") or "Event"
        src_ip = event.get("src_ip") or details.get("source_ip") or details.get("src_ip") or details.get("ip")
        dst_ip = event.get("dst_ip") or details.get("destination_ip") or details.get("dst_ip")
        severity = event.get("severity") or details.get("severity") or "low"
        is_attack_path = event.get("is_attack_path")
        if is_attack_path is None:
            is_attack_path = details.get("is_attack_path", False)
        protocol = event.get("protocol") or details.get("protocol")
        timestamp = event.get("timestamp") or details.get("timestamp") or ""
        if hasattr(timestamp, "isoformat"):
            timestamp = timestamp.isoformat()
        return {
            "id": str(event.get("id", "")),
            "host": str(host) if host else None,
            "user": str(user) if user and str(user) not in ("SYSTEM", "unknown", "") else None,
            "action": str(action),
            "src_ip": str(src_ip) if src_ip else None,
            "dst_ip": str(dst_ip) if dst_ip else None,
            "severity": str(severity).lower(),
            "is_attack_path": bool(is_attack_path or severity in ("critical", "high")),
            "protocol": str(protocol) if protocol else None,
            "timestamp": str(timestamp),
        }

    # ORM Event model
    details = getattr(event, "details", {}) or {}
    host = details.get("host") or details.get("Computer") or details.get("WorkstationName")
    user = details.get("user") or details.get("username") or details.get("TargetUserName")
    action = details.get("action") or details.get("message") or details.get("Message") or getattr(event, "event_type", "Event")
    src_ip = details.get("source_ip") or details.get("src_ip") or details.get("ip")
    dst_ip = details.get("destination_ip") or details.get("dst_ip")
    severity = details.get("severity") or "low"
    is_attack_path = details.get("is_attack_path", False) or severity in ("critical", "high")
    protocol = details.get("protocol")
    ts = getattr(event, "timestamp", None)
    timestamp_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts or "")

    return {
        "id": str(getattr(event, "id", "")),
        "host": str(host) if host else None,
        "user": str(user) if user and str(user) not in ("SYSTEM", "unknown", "") else None,
        "action": str(action),
        "src_ip": str(src_ip) if src_ip else None,
        "dst_ip": str(dst_ip) if dst_ip else None,
        "severity": str(severity).lower(),
        "is_attack_path": bool(is_attack_path),
        "protocol": str(protocol) if protocol else None,
        "timestamp": timestamp_str,
    }


def build_attack_graph(events: List[Any], attack_path_only: bool = False) -> Dict[str, Any]:
    """
    Constructs directional graph topology (nodes and edges) from incident events.
    Matches the schema expected by the frontend GraphView component.
    """
    nodes_map: Dict[str, Dict[str, Any]] = {}
    edges_map: Dict[str, Dict[str, Any]] = {}

    for raw_event in events:
        evt = extract_event_fields(raw_event)
        is_attack = evt["is_attack_path"]
        timestamp = evt["timestamp"]
        severity = evt["severity"]

        # 1. Host Node
        if evt["host"]:
            host_id = f"host-{evt['host']}"
            if host_id not in nodes_map:
                nodes_map[host_id] = {
                    "id": host_id,
                    "label": evt["host"],
                    "type": "host",
                    "is_compromised": is_attack,
                    "is_attack_path": is_attack,
                    "event_count": 1,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                }
            else:
                nodes_map[host_id]["event_count"] += 1
                if is_attack:
                    nodes_map[host_id]["is_compromised"] = True
                    nodes_map[host_id]["is_attack_path"] = True
                nodes_map[host_id]["last_seen"] = timestamp

        # 2. User Node
        if evt["user"]:
            user_id = f"user-{evt['user']}"
            if user_id not in nodes_map:
                nodes_map[user_id] = {
                    "id": user_id,
                    "label": f"user: {evt['user']}",
                    "type": "user",
                    "is_compromised": is_attack,
                    "is_attack_path": is_attack,
                    "event_count": 1,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                }
            else:
                nodes_map[user_id]["event_count"] += 1
                if is_attack:
                    nodes_map[user_id]["is_compromised"] = True
                    nodes_map[user_id]["is_attack_path"] = True
                nodes_map[user_id]["last_seen"] = timestamp

            # Connect User -> Host
            if evt["host"]:
                host_id = f"host-{evt['host']}"
                edge_id = f"edge-{user_id}-{host_id}"
                action_label = evt["action"][:30] + ("..." if len(evt["action"]) > 30 else "")
                if edge_id not in edges_map:
                    edges_map[edge_id] = {
                        "id": edge_id,
                        "source": user_id,
                        "target": host_id,
                        "label": action_label,
                        "timestamp": timestamp,
                        "count": 1,
                        "is_attack_path": is_attack,
                        "severity": severity,
                    }
                else:
                    edges_map[edge_id]["count"] += 1
                    if is_attack:
                        edges_map[edge_id]["is_attack_path"] = True

        # 3. Source IP Node
        if evt["src_ip"]:
            ip_id = f"ip-{evt['src_ip']}"
            if ip_id not in nodes_map:
                nodes_map[ip_id] = {
                    "id": ip_id,
                    "label": evt["src_ip"],
                    "type": "ip",
                    "is_compromised": is_attack,
                    "is_attack_path": is_attack,
                    "event_count": 1,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                }
            else:
                nodes_map[ip_id]["event_count"] += 1
                if is_attack:
                    nodes_map[ip_id]["is_compromised"] = True
                    nodes_map[ip_id]["is_attack_path"] = True

            # Connect IP -> Destination IP or Host
            if evt["dst_ip"]:
                dst_id = f"ip-{evt['dst_ip']}"
                if dst_id not in nodes_map:
                    nodes_map[dst_id] = {
                        "id": dst_id,
                        "label": evt["dst_ip"],
                        "type": "ip",
                        "is_compromised": is_attack,
                        "is_attack_path": is_attack,
                        "event_count": 1,
                        "first_seen": timestamp,
                        "last_seen": timestamp,
                    }
                edge_id = f"edge-{ip_id}-{dst_id}"
                label = f"{evt['protocol']}" if evt.get("protocol") else evt["action"][:25]
                if edge_id not in edges_map:
                    edges_map[edge_id] = {
                        "id": edge_id,
                        "source": ip_id,
                        "target": dst_id,
                        "label": label,
                        "protocol": evt.get("protocol"),
                        "timestamp": timestamp,
                        "count": 1,
                        "is_attack_path": is_attack,
                        "severity": severity,
                    }
                else:
                    edges_map[edge_id]["count"] += 1
            elif evt["host"]:
                host_id = f"host-{evt['host']}"
                edge_id = f"edge-{ip_id}-{host_id}"
                if edge_id not in edges_map:
                    edges_map[edge_id] = {
                        "id": edge_id,
                        "source": ip_id,
                        "target": host_id,
                        "label": evt["action"][:25],
                        "timestamp": timestamp,
                        "count": 1,
                        "is_attack_path": is_attack,
                        "severity": severity,
                    }
                else:
                    edges_map[edge_id]["count"] += 1

    nodes = list(nodes_map.values())
    edges = list(edges_map.values())

    if attack_path_only:
        active_node_ids = {n["id"] for n in nodes if n["is_attack_path"] or n["is_compromised"]}
        nodes = [n for n in nodes if n["id"] in active_node_ids]
        edges = [
            e for e in edges
            if e["source"] in active_node_ids and e["target"] in active_node_ids and e["is_attack_path"]
        ]

    return {
        "nodes": nodes,
        "edges": edges,
    }
