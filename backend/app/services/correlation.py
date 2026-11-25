# Correlation service
from datetime import datetime, timezone
import ipaddress
from typing import Any, Dict, List, Optional, Set, Tuple

from .event_ordering import event_sort_key, sort_events


MIN_CHAIN_CONFIDENCE: float = 0.70

_UNKNOWN_HOSTS = {"", "-", "unknown", "unknown_host"}
_UNKNOWN_USERS = {"", "-", "unknown", "system"}


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _is_internal_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return addr.is_loopback or addr.is_link_local or any(
        addr in ipaddress.ip_network(net)
        for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    )


def _parse_ts(ts_str: str) -> Optional[float]:
    if not ts_str:
        return None
    try:
        dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError):
        return None


def _normalize_event(e: Any) -> Dict[str, Any]:
    if isinstance(e, dict):
        details = e.get("details", {}) or {}
        if not isinstance(details, dict):
            details = {}
        ev_type = str(e.get("event_type") or "")
        category = str(e.get("category") or details.get("category") or "")
        ts = e.get("timestamp") or details.get("timestamp") or ""
        return {
            "id": str(e.get("id", "")),
            "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts or ""),
            "host": str(e.get("host") or details.get("host") or details.get("Computer") or details.get("hostname") or ""),
            "user": str(e.get("user") or details.get("user") or details.get("username") or ""),
            "src_ip": str(e.get("src_ip") or details.get("source_ip") or details.get("src_ip") or ""),
            "dst_ip": str(e.get("dst_ip") or details.get("destination_ip") or details.get("dst_ip") or ""),
            "severity": str(e.get("severity") or details.get("severity") or "low"),
            "action": str(e.get("action") or details.get("action") or details.get("message") or ev_type),
            "event_type": ev_type,
            "category": category,
            "is_attack_path": bool(e.get("is_attack_path") or details.get("is_attack_path")),
            "source_file": str(e.get("source_file") or details.get("source_file") or e.get("source") or ""),
            "source_record_id": e.get("source_record_id") or details.get("source_record_id") or details.get("record_id") or details.get("event_record_id"),
            "fingerprint": e.get("fingerprint") or "",
            "details": details,
        }

    details = getattr(e, "details", {}) or {}
    if not isinstance(details, dict):
        details = {}
    ev_type = str(getattr(e, "event_type", "") or "")
    category = str(getattr(e, "category", None) or details.get("category") or "")
    ts = getattr(e, "timestamp", "")
    return {
        "id": str(getattr(e, "id", "")),
        "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts or ""),
        "host": str(getattr(e, "host", None) or details.get("host") or details.get("Computer") or details.get("hostname") or ""),
        "user": str(getattr(e, "user", None) or details.get("user") or details.get("username") or ""),
        "src_ip": str(getattr(e, "src_ip", None) or details.get("source_ip") or details.get("src_ip") or ""),
        "dst_ip": str(getattr(e, "dst_ip", None) or details.get("destination_ip") or details.get("dst_ip") or ""),
        "severity": str(details.get("severity") or getattr(e, "severity", None) or "low"),
        "action": str(details.get("action") or details.get("message") or ev_type),
        "event_type": ev_type,
        "category": category,
        "is_attack_path": bool(details.get("is_attack_path", False)),
        "source_file": str(details.get("source_file") or getattr(e, "source", "") or ""),
        "source_record_id": details.get("source_record_id") or details.get("record_id") or details.get("event_record_id"),
        "fingerprint": getattr(e, "fingerprint", "") or "",
        "details": details,
    }


def _extract_detection_fields(d: Any) -> Dict[str, Any]:
    if isinstance(d, dict):
        ri = d.get("rule_information") or {}
        if not isinstance(ri, dict):
            ri = {}
        is_fp = bool(d.get("false_positive") or d.get("is_false_positive"))
        event_ids = d.get("matching_event_ids") or d.get("matched_event_ids") or d.get("event_ids") or ri.get("matching_event_ids") or []
        tactic = str(d.get("mitre_tactic") or ri.get("tactic") or "").strip()
        target_host = str(
            d.get("target_host") or ri.get("target_host") or ri.get("host") or d.get("host")
            or ((ri.get("hosts") or d.get("hosts") or [None])[0] or "")
        ).strip()
        src_ips = [
            str(ip).strip()
            for ip in (
                *(d.get("source_ips") or []),
                *(ri.get("source_ips") or []),
                *(ri.get("src_ips") or []),
                d.get("src_ip"),
                ri.get("src_ip"),
            )
            if ip
        ]
        return {
            "is_fp": is_fp,
            "event_ids": [str(eid) for eid in event_ids if eid],
            "tactic": tactic,
            "target_host": target_host,
            "src_ips": src_ips,
        }

    ri = getattr(d, "rule_information", None) or {}
    if not isinstance(ri, dict):
        ri = {}
    is_fp = bool(getattr(d, "is_false_positive", False) or getattr(d, "false_positive", False))
    event_ids = getattr(d, "matched_event_ids", None) or getattr(d, "matching_event_ids", None) or ri.get("matching_event_ids") or []
    tactic = str(getattr(d, "mitre_tactic", None) or ri.get("tactic") or "").strip()
    target_host = str(
        ri.get("target_host") or ri.get("host") or ((ri.get("hosts") or [None])[0] or "")
    ).strip()
    src_ips = [
        str(ip).strip()
        for ip in (
            *(ri.get("source_ips") or []),
            *(ri.get("src_ips") or []),
            ri.get("src_ip"),
        )
        if ip
    ]
    return {
        "is_fp": is_fp,
        "event_ids": [str(eid) for eid in event_ids if eid],
        "tactic": tactic,
        "target_host": target_host,
        "src_ips": src_ips,
    }


def correlate_attack_chains(
    events: List[Any],
    window_minutes: int = 45,
    min_confidence: float = MIN_CHAIN_CONFIDENCE,
    detections: Optional[List[Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Reconstruct detection-backed attack chains grouped by target host.

    1. Start only from events linked to non-false-positive detections.
    2. Group by target host; build one chain per group with >= 3 distinct tactics.
    3. Include additional events from the same source IPs inside the chain span
       (never adding events solely because they share the host, and excluding
       metrics/context rows unless explicitly linked to a detection).
    """
    if not events or not detections:
        return []

    norm_events = sort_events(_normalize_event(e) for e in events)
    events_by_id = {ev["id"]: ev for ev in norm_events if ev["id"]}
    if not events_by_id:
        return []

    non_ip_hosts = {
        ev["host"]
        for ev in norm_events
        if ev["host"].strip().casefold() not in _UNKNOWN_HOSTS and not _is_ip_literal(ev["host"])
    }
    single_host = next(iter(non_ip_hosts)) if len(non_ip_hosts) == 1 else ""

    # 1 & 2. Collect non-false-positive detections and group by target host
    groups: Dict[str, Dict[str, Any]] = {}
    for raw_det in detections:
        det = _extract_detection_fields(raw_det)
        if det["is_fp"]:
            continue

        linked_evts = [events_by_id[eid] for eid in det["event_ids"] if eid in events_by_id]
        if not linked_evts:
            continue

        host = det["target_host"]
        if host.casefold() in _UNKNOWN_HOSTS or _is_ip_literal(host):
            host = next(
                (
                    ev["host"]
                    for ev in linked_evts
                    if ev["host"].strip().casefold() not in _UNKNOWN_HOSTS and not _is_ip_literal(ev["host"])
                ),
                single_host or "unknown_host",
            )

        grp = groups.setdefault(host, {"linked_ids": set(), "detections": [], "det_src_ips": set()})
        grp["linked_ids"].update(ev["id"] for ev in linked_evts)
        for ip in det["src_ips"]:
            if ip and ip != "-":
                grp["det_src_ips"].add(ip)

        earliest_ts = min(ev["timestamp"] for ev in linked_evts)
        grp["detections"].append((earliest_ts, det["tactic"]))

    sev_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    chains: List[Dict[str, Any]] = []

    for host, grp in groups.items():
        ordered_dets: List[Tuple[str, str]] = sorted(
            [(ts, tac) for ts, tac in grp["detections"] if tac],
            key=lambda item: (item[0], item[1]),
        )
        distinct_tactics = {tac for _, tac in ordered_dets}
        if len(distinct_tactics) < 3:
            continue

        confidence_score = min(0.95, round(0.40 + (0.08 * len(distinct_tactics)), 2))
        if confidence_score < min_confidence:
            continue

        linked_events = sorted(
            (events_by_id[eid] for eid in grp["linked_ids"]),
            key=lambda ev: (ev["timestamp"], event_sort_key(ev)[1:]),
        )
        start_time = linked_events[0]["timestamp"]
        end_time = linked_events[-1]["timestamp"]
        start_sec = _parse_ts(start_time)
        end_sec = _parse_ts(end_time)

        # 3. Source IPs from linked events (and findings), excluding internal interface self-flows
        candidate_src_ips: Set[str] = set(grp["det_src_ips"])
        for ev in linked_events:
            sip = ev["src_ip"].strip()
            if not sip or sip == "-":
                continue
            # Outbound flows where host == src_ip and dst_ip is present represent the server itself, not the attacker source
            if ev["host"].strip() == sip and ev["dst_ip"].strip():
                continue
            candidate_src_ips.add(sip)
        external_src_ips = {ip for ip in candidate_src_ips if _is_ip_literal(ip) and not _is_internal_ip(ip)}
        chain_src_ips = sorted(external_src_ips or candidate_src_ips)
        chain_src_ip_set = set(chain_src_ips)

        chain_event_ids = set(grp["linked_ids"])
        chain_events = list(linked_events)

        for ev in norm_events:
            if ev["id"] in chain_event_ids:
                continue
            # Exclude metrics/context rows unless explicitly linked to a detection
            if ev["event_type"] == "metric" or ev["category"] == "context" or ev["event_type"] == "vuln_scan":
                continue
            if ev["src_ip"].strip() not in chain_src_ip_set:
                continue
            ev_sec = _parse_ts(ev["timestamp"])
            if start_sec is not None and end_sec is not None and ev_sec is not None:
                if not (start_sec <= ev_sec <= end_sec):
                    continue
            elif not (start_time <= ev["timestamp"] <= end_time):
                continue
            chain_event_ids.add(ev["id"])
            chain_events.append(ev)

        chain_events = sorted(
            chain_events,
            key=lambda ev: (ev["timestamp"], event_sort_key(ev)[1:]),
        )

        chain_entities: Set[str] = set()
        if host and host.casefold() not in _UNKNOWN_HOSTS:
            chain_entities.add(f"host:{host}")
        for sip in chain_src_ips:
            chain_entities.add(f"ip:{sip}")
        highest_sev = "low"
        max_lvl = 1
        for ce in chain_events:
            if ce["host"] and ce["host"].casefold() not in _UNKNOWN_HOSTS and not _is_ip_literal(ce["host"]):
                chain_entities.add(f"host:{ce['host']}")
            if ce["user"] and ce["user"].strip().casefold() not in _UNKNOWN_USERS:
                chain_entities.add(f"user:{ce['user']}")
            if ce["src_ip"] and ce["src_ip"] != "-":
                chain_entities.add(f"ip:{ce['src_ip']}")
            if ce["dst_ip"] and ce["dst_ip"] != "-":
                chain_entities.add(f"ip:{ce['dst_ip']}")
            lvl = sev_levels.get(ce["severity"].lower(), 1)
            if lvl > max_lvl:
                max_lvl = lvl
                highest_sev = ce["severity"].lower()

        first_tactic = ordered_dets[0][1]
        last_tactic = ordered_dets[-1][1]
        src_prefix = ", ".join(chain_src_ips)
        title = (
            f"{src_prefix} -> {host}: {first_tactic} -> {last_tactic}"
            if src_prefix
            else f"{host}: {first_tactic} -> {last_tactic}"
        )

        chains.append({
            "id": f"chain-{len(chains) + 1}",
            "name": title,
            "events": chain_events,
            "entities": sorted(chain_entities),
            "start_time": chain_events[0]["timestamp"],
            "end_time": chain_events[-1]["timestamp"],
            "confidence_score": confidence_score,
            "highest_severity": highest_sev,
        })

    return chains
