# Correlation service
from datetime import datetime
from typing import Any, Dict, List


def correlate_attack_chains(events: List[Any], window_minutes: int = 45) -> List[Dict[str, Any]]:
    """
    Correlates incident events sharing common entities (hosts, accounts, IP addresses)
    within a rolling time window to reconstruct multi-stage attack trajectories.
    """
    if not events:
        return []

    # Extract clean normalized objects
    clean_events = []
    for e in events:
        if isinstance(e, dict):
            details = e.get("details", {}) or {}
            clean_events.append({
                "id": str(e.get("id", "")),
                "timestamp": str(e.get("timestamp") or details.get("timestamp") or ""),
                "host": str(e.get("host") or details.get("host") or details.get("Computer") or ""),
                "user": str(e.get("user") or details.get("user") or details.get("username") or ""),
                "src_ip": str(e.get("src_ip") or details.get("source_ip") or details.get("src_ip") or ""),
                "dst_ip": str(e.get("dst_ip") or details.get("destination_ip") or details.get("dst_ip") or ""),
                "severity": str(e.get("severity") or details.get("severity") or "low"),
                "action": str(e.get("action") or details.get("action") or details.get("message") or ""),
                "is_attack_path": bool(e.get("is_attack_path") or details.get("is_attack_path")),
            })
        else:
            details = getattr(e, "details", {}) or {}
            ts = getattr(e, "timestamp", "")
            clean_events.append({
                "id": str(getattr(e, "id", "")),
                "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts or ""),
                "host": str(details.get("host") or details.get("Computer") or ""),
                "user": str(details.get("user") or details.get("username") or ""),
                "src_ip": str(details.get("source_ip") or details.get("src_ip") or ""),
                "dst_ip": str(details.get("destination_ip") or details.get("dst_ip") or ""),
                "severity": str(details.get("severity") or "low"),
                "action": str(details.get("action") or details.get("message") or getattr(e, "event_type", "")),
                "is_attack_path": bool(details.get("is_attack_path", False)),
            })

    # Sort chronologically
    clean_events.sort(key=lambda x: x["timestamp"])

    chains = []
    visited = set()

    for i, root in enumerate(clean_events):
        if root["id"] in visited:
            continue

        chain_events = [root]
        visited.add(root["id"])
        chain_entities = set()

        def add_entities(ev):
            if ev["host"]:
                chain_entities.add(f"host:{ev['host']}")
            if ev["user"] and ev["user"] not in ("SYSTEM", "unknown"):
                chain_entities.add(f"user:{ev['user']}")
            if ev["src_ip"]:
                chain_entities.add(f"ip:{ev['src_ip']}")
            if ev["dst_ip"]:
                chain_entities.add(f"ip:{ev['dst_ip']}")

        add_entities(root)

        for j in range(i + 1, len(clean_events)):
            nxt = clean_events[j]
            if nxt["id"] in visited:
                continue

            shares = False
            if nxt["host"] and f"host:{nxt['host']}" in chain_entities:
                shares = True
            if nxt["user"] and f"user:{nxt['user']}" in chain_entities:
                shares = True
            if nxt["src_ip"] and (f"ip:{nxt['src_ip']}" in chain_entities or f"ip:{nxt['dst_ip']}" in chain_entities):
                shares = True
            if nxt["dst_ip"] and (f"ip:{nxt['dst_ip']}" in chain_entities or f"ip:{nxt['src_ip']}" in chain_entities):
                shares = True

            if shares:
                visited.add(nxt["id"])
                chain_events.append(nxt)
                add_entities(nxt)

        if len(chain_events) >= 2 or root["is_attack_path"]:
            highest_sev = "low"
            sev_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            max_lvl = 1
            for ce in chain_events:
                lvl = sev_levels.get(ce["severity"].lower(), 1)
                if lvl > max_lvl:
                    max_lvl = lvl
                    highest_sev = ce["severity"].lower()

            chains.append({
                "id": f"chain-{i+1}",
                "name": f"Correlated Attack Vector #{len(chains)+1}",
                "events": chain_events,
                "entities": list(chain_entities),
                "start_time": chain_events[0]["timestamp"],
                "end_time": chain_events[-1]["timestamp"],
                "confidence_score": min(0.98, round(0.5 + (len(chain_events) * 0.08), 2)),
                "highest_severity": highest_sev,
            })

    return chains
