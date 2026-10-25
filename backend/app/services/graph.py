# Graph service (Stage 7)
# B2/B3 fixes:
# - No hardcoded subnet_map (violates Rule 2).
# - IP-to-host merging is purely evidence-derived.
# - Adversary styling only on *adversary_infrastructure* entities from findings.
# - Victim/compromised highlight only on target hosts confirmed by findings.
# - One node per entity; no duplicate HOST and EXT for the same address.
import re
import ipaddress
from typing import Any, Dict, List, Set, Tuple
from app.services.entity_classification import is_internal_ip
from app.services.report_fixes import norm_user, format_user


def is_private_ip(ip_str: str) -> bool:
    """Returns True if the given IP address is private (RFC 1918 / loopback)."""
    return is_internal_ip(ip_str)


def _is_ip_address(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
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
    if str(host or "").casefold() in {"unknown", "unknown_host", "-"}:
        host = None
    workstation = details.get("WorkstationName")

    raw_extra = details.get("extra") if isinstance(details.get("extra"), dict) else {}
    raw_msg = str(details.get("raw_message") or details.get("raw") or raw_extra.get("raw_message") or "")
    if not host:
        iso_log_match = re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+([A-Za-z0-9_.-]+)", raw_msg)
        syslog_match = re.match(r"^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+([a-zA-Z0-9_\-\.]+)", raw_msg)
        host_match = iso_log_match or syslog_match
        if host_match:
            host = host_match.group(1)

    user = (
        (event.get("user") if is_dict else getattr(event, "user", None))
        or details.get("user")
        or details.get("username")
        or details.get("TargetUserName")
        or details.get("SubjectUserName")
    )
    if not user or user in ("unknown", "-"):
        user_match = re.search(r"\buser(?:name)?=(?:\"([^\"]+)\"|([^\s]+))", raw_msg, re.IGNORECASE)
        if user_match:
            user = user_match.group(1) or user_match.group(2)
        else:
            recipient_match = re.search(r"\bto=<([^>]+)>", raw_msg, re.IGNORECASE)
            if recipient_match:
                user = recipient_match.group(1)
    extra = details.get("extra") if isinstance(details.get("extra"), dict) else {}
    domain = details.get("TargetDomainName") or details.get("domain") or extra.get("TargetDomainName") or extra.get("domain")
    if user and domain and "\\" not in str(user) and "@" not in str(user) and str(user).casefold() not in {"system", "localsystem", "-"}:
        user = f"{domain}\\{user}"
    if user in ("SYSTEM", "unknown", "-", ""):
        user = None

    action = (
        (event.get("action") if is_dict else getattr(event, "action", None))
        or details.get("action")
        or details.get("message")
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
        or any(w in str(action).lower() for w in [
            "cvlk", "rclone", "psexec", "mimikatz", "vssadmin", "ntdsutil",
            "comsvcs", "shadow", "drop", "authorized_keys", "useradd",
            "wget", "/tmp/", "chmod +x", "mysqldump", "scp ", "/dev/tcp",
            "history -c", "crontab", "miner", "3333", "4444"
        ])
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


def build_attack_graph(
    events: List[Any],
    attack_path_only: bool = False,
    findings: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """
    Constructs directional graph topology with IP-to-host merging, distinct node roles,
    and aggregated edges with counts.

    B2: IP-to-host merging is evidence-derived only (no hardcoded map).
    B3: adversary vs victim roles are determined from findings, not from
        raw is_attack flag.
    """
    nodes_map: Dict[str, Dict[str, Any]] = {}
    edges_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    ip_to_host: Dict[str, str] = {}

    extracted_events = [extract_event_fields(e) for e in events]
    observed_domains: Dict[str, Set[str]] = {}
    for evt in extracted_events:
        user = evt["user"] or ""
        if "\\" in user:
            domain, username = user.split("\\", 1)
            observed_domains.setdefault(username.casefold(), set()).add(domain)
        elif "@" in user:
            username, domain = user.split("@", 1)
            observed_domains.setdefault(username.casefold(), set()).add(domain.split(".", 1)[0])
    for evt in extracted_events:
        user = evt["user"] or ""
        if "\\" not in user and "@" not in user:
            domains = observed_domains.get(user.casefold(), set())
            if len(domains) == 1:
                evt["user"] = f"{next(iter(domains))}\\{user}"

    # B2 Pass 1: Build IP-to-host mapping from evidence records containing both.
    # No pre-seeded hardcoded map — only what's in the evidence.
    ip_host_candidates: Dict[str, Dict[str, int]] = {}
    for evt in extracted_events:
        h = evt["workstation"] or evt["host"]
        ip = evt["src_ip"]
        if h and not _is_ip_address(h) and ip and is_private_ip(ip):
            candidates = ip_host_candidates.setdefault(ip, {})
            candidates[h] = candidates.get(h, 0) + (4 if evt["workstation"] else 1)
    for ip, candidates in ip_host_candidates.items():
        best = max(candidates.values())
        winners = [host for host, score in candidates.items() if score == best]
        if len(winners) == 1:
            ip_to_host[ip] = winners[0]

    # B3: Determine adversary infrastructure and compromised hosts from findings
    adversary_ips: Set[str] = set()
    compromised_hosts: Set[str] = set()
    if findings:
        for f in findings:
            role = f.get("actor_role") or ""
            actor = f.get("actor") or ""
            if role == "adversary_infrastructure" and actor:
                adversary_ips.add(actor)
            target_role = f.get("target_role") or ""
            target = f.get("target_host") or ""
            if target_role == "compromised_host" and target:
                compromised_hosts.add(target)

    # Pass 2: Create nodes and aggregate edges
    for evt in extracted_events:
        is_attack = evt["is_attack_path"]
        ts = evt["timestamp"]
        evt_id = evt["id"]

        # Resolve host (merge private IP into host if evidence-derived mapping exists)
        effective_host = evt["host"]
        if effective_host and _is_ip_address(effective_host):
            effective_host = ip_to_host.get(effective_host) if is_private_ip(effective_host) else None
        if effective_host is None and evt["workstation"] and not _is_ip_address(evt["workstation"]):
            effective_host = evt["workstation"]
        if not effective_host and evt["src_ip"] and evt["src_ip"] in ip_to_host:
            effective_host = ip_to_host[evt["src_ip"]]

        # 1. Host Node — only mark compromised if findings confirm it (B3)
        if effective_host:
            h_id = f"host-{effective_host}"
            is_compromised_by_finding = effective_host in compromised_hosts
            if h_id not in nodes_map:
                nodes_map[h_id] = {
                    "id": h_id,
                    "label": effective_host,
                    "type": "host",
                    "role": "compromised_host" if is_compromised_by_finding else "internal_host",
                    "is_compromised": is_compromised_by_finding,
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
                if is_compromised_by_finding:
                    nodes_map[h_id]["is_compromised"] = True
                    nodes_map[h_id]["role"] = "compromised_host"
                if is_attack:
                    nodes_map[h_id]["is_attack_path"] = True
                nodes_map[h_id]["last_seen"] = ts

        # 2. User Node
        if evt["user"]:
            identity = norm_user(evt["user"]) or str(evt["user"]).casefold()
            display_user = format_user(evt["user"])
            user_domain = display_user.split("\\", 1)[0] if "\\" in display_user else ""
            user_name = display_user.split("\\", 1)[-1]
            u_id = f"user-{identity}"
            if u_id not in nodes_map:
                nodes_map[u_id] = {
                    "id": u_id,
                    "label": display_user,
                    "username": user_name,
                    "domain": user_domain,
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

        # 3. Source IP
        src_ip = evt["src_ip"]
        src_node_id = None
        if src_ip:
            if src_ip in ip_to_host:
                src_node_id = f"host-{ip_to_host[src_ip]}"
            else:
                is_priv = is_private_ip(src_ip)
                # B3: adversary role from findings, not from is_attack alone
                is_adversary = src_ip in adversary_ips
                src_node_id = f"ip-{src_ip}"
                node_type = "ip"
                node_role = "adversary_infrastructure" if is_adversary else ("internal_host" if is_priv else "external_ip")
                if src_node_id not in nodes_map:
                    nodes_map[src_node_id] = {
                        "id": src_node_id,
                        "label": src_ip,
                        "type": node_type,
                        "role": node_role,
                        "is_compromised": is_adversary,
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
                    if is_adversary:
                        nodes_map[src_node_id]["is_compromised"] = True
                        nodes_map[src_node_id]["role"] = "adversary_infrastructure"
                    if is_attack:
                        nodes_map[src_node_id]["is_attack_path"] = True

        # 4. Destination IP
        dst_ip = evt["dst_ip"]
        dst_node_id = None
        if dst_ip:
            if dst_ip in ip_to_host:
                dst_node_id = f"host-{ip_to_host[dst_ip]}"
            else:
                is_priv = is_private_ip(dst_ip)
                is_adversary_dst = dst_ip in adversary_ips
                dst_node_id = f"ip-{dst_ip}"
                node_type = "ip"
                node_role = "adversary_infrastructure" if is_adversary_dst else ("internal_host" if is_priv else "external_ip")
                if dst_node_id not in nodes_map:
                    nodes_map[dst_node_id] = {
                        "id": dst_node_id,
                        "label": dst_ip,
                        "type": node_type,
                        "role": node_role,
                        "is_compromised": is_adversary_dst,
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
                    if is_adversary_dst:
                        nodes_map[dst_node_id]["role"] = "adversary_infrastructure"
                        nodes_map[dst_node_id]["is_compromised"] = True
                    if is_attack:
                        nodes_map[dst_node_id]["is_attack_path"] = True

        # Connect Source Node -> Destination Node
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
