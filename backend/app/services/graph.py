# Graph service (Stage 7)
# B2/B3 fixes:
# - No hardcoded subnet_map (violates Rule 2).
# - IP-to-host merging is purely evidence-derived.
# - Adversary styling only on *adversary_infrastructure* entities from findings.
# - Victim/compromised highlight only on target hosts confirmed by findings.
# - One node per entity; no duplicate HOST and EXT for the same address.
from datetime import datetime, timezone
import os
import re
import ipaddress
from typing import Any, Dict, List, Set, Tuple
from app.services.entity_classification import (
    build_host_alias_map,
    host_alias_ips,
    is_internal_ip,
    is_process_or_command_name,
    is_valid_host_name,
    strip_target_alias_ips,
)
from app.services.report_fixes import norm_user, format_user

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_URL_HOST_RE = re.compile(r"https?://([A-Za-z0-9.-]+)(?::\d+)?", re.IGNORECASE)
_UID_TOKEN_RE = re.compile(r"^uid=(\d+)$", re.IGNORECASE)
_USERADD_AUTH_RE = re.compile(r"\buseradd:\s*new user:\s*name=([A-Za-z0-9_.$-]+),\s*UID=(\d+)", re.IGNORECASE)
_USERADD_CMD_RE = re.compile(
    r"\b(?:useradd|adduser)\b(?:\s+-[A-Za-z]+\s+\S+|\s+-[A-Za-z]+)*\s+([A-Za-z0-9_.$-]+)\s*$",
    re.IGNORECASE,
)
_PAM_NAMED_UID_RE = re.compile(r"\bpam_unix\([^)]*\):.*?\bby\s+([A-Za-z0-9_.$-]+)\(uid=(\d+)\)", re.IGNORECASE)
_PAM_ANON_UID_RE = re.compile(r"\bpam_unix\([^)]*\):.*?\bsession opened\b.*?\bby\s+\(uid=(\d+)\)", re.IGNORECASE)
_SUDO_FOR_USER_RE = re.compile(r"\bsudo_command\s+for\s+([A-Za-z0-9_.$-]+)\b", re.IGNORECASE)
_DEV_TCP_RE = re.compile(r"/dev/tcp/(\d{1,3}(?:\.\d{1,3}){3})/\d+", re.IGNORECASE)


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
    if not is_valid_host_name(host):
        host = None
    workstation = details.get("WorkstationName")
    if workstation and not is_valid_host_name(workstation):
        workstation = None

    raw_extra = details.get("extra") if isinstance(details.get("extra"), dict) else {}
    raw_msg = str(details.get("raw_message") or details.get("raw") or raw_extra.get("raw_message") or "")
    ev_type = (event.get("event_type") if is_dict else getattr(event, "event_type", "")) or ""
    if not host and details.get("thread_id") is None and ev_type not in {"db_query", "db_connect"}:
        iso_log_match = re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+([A-Za-z0-9_.-]+)", raw_msg)
        syslog_match = re.match(r"^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+([a-zA-Z0-9_\-\.]+)", raw_msg)
        host_match = iso_log_match or syslog_match
        if host_match and is_valid_host_name(host_match.group(1)):
            host = host_match.group(1)

    raw_proc = (
        (event.get("process") if is_dict else getattr(event, "process", None))
        or details.get("process_name")
        or details.get("process")
        or details.get("comm")
        or details.get("exe")
        or details.get("Image")
        or raw_extra.get("process_name")
        or raw_extra.get("comm")
        or raw_extra.get("exe")
    )
    process_name = (
        os.path.basename(str(raw_proc).strip().strip('"\'').replace("\\", "/"))
        if raw_proc
        else None
    )
    command_line = (
        (event.get("command_line") if is_dict else getattr(event, "command_line", None))
        or details.get("command_line")
        or details.get("CommandLine")
        or raw_extra.get("command_line")
    )

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
    if user and is_process_or_command_name(user, process_name=process_name, command_line=command_line):
        user = None
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
        "event_type": str(ev_type),
        "host": str(host) if host and is_valid_host_name(host) else None,
        "workstation": str(workstation) if workstation and is_valid_host_name(workstation) else None,
        "user": str(user) if user else None,
        "process": str(process_name) if process_name else None,
        "command_line": str(command_line) if command_line else None,
        "action": str(action),
        "raw_message": raw_msg,
        "src_ip": str(src_ip) if src_ip else None,
        "dst_ip": str(dst_ip) if dst_ip else None,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "is_attack_path": is_attack,
        "timestamp": timestamp_str,
    }


def _parse_ts_seconds(ts_str: str) -> float | None:
    if not ts_str:
        return None
    try:
        dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError):
        return None


def _extract_uid_account_map(extracted_events: List[Dict[str, Any]]) -> Tuple[Dict[Tuple[str, str], str], Dict[str, str]]:
    """Map (host, uid=N) -> account name strictly from sudo/auth/useradd log evidence."""
    candidates: Dict[Tuple[str, str], Set[str]] = {}
    sudo_actors_by_host: Dict[str, List[Tuple[float | None, str]]] = {}
    pam_uid_by_host: Dict[str, List[Tuple[float | None, str]]] = {}

    for evt in extracted_events:
        host_key = (evt.get("host") or "").casefold()
        text = f"{evt.get('action') or ''} {evt.get('raw_message') or ''}"
        ev_type = (evt.get("event_type") or "").casefold()

        for rx in (_USERADD_AUTH_RE, _PAM_NAMED_UID_RE):
            m = rx.search(text)
            if m:
                acct, uid_num = m.group(1), m.group(2)
                if acct and not _UID_TOKEN_RE.match(acct) and not is_process_or_command_name(acct):
                    candidates.setdefault((host_key, f"uid={uid_num}"), set()).add(acct)

        ts_sec = _parse_ts_seconds(evt.get("timestamp") or "")
        if ev_type == "sudo_command" or _SUDO_FOR_USER_RE.search(text):
            sudo_m = _SUDO_FOR_USER_RE.search(text)
            acct = (sudo_m.group(1) if sudo_m else None) or evt.get("user")
            if acct and not _UID_TOKEN_RE.match(str(acct)) and not is_process_or_command_name(acct):
                sudo_actors_by_host.setdefault(host_key, []).append((ts_sec, str(acct)))

        pam_m = _PAM_ANON_UID_RE.search(text)
        if pam_m:
            pam_uid_by_host.setdefault(host_key, []).append((ts_sec, f"uid={pam_m.group(1)}"))

    for host_key, pam_entries in pam_uid_by_host.items():
        sudo_entries = sudo_actors_by_host.get(host_key, [])
        for pam_ts, uid_token in pam_entries:
            if pam_ts is None:
                continue
            nearby_users = {
                acct
                for sudo_ts, acct in sudo_entries
                if sudo_ts is not None and abs(pam_ts - sudo_ts) <= 10.0
            }
            if len(nearby_users) == 1:
                candidates.setdefault((host_key, uid_token), set()).add(next(iter(nearby_users)))

    exact_map: Dict[Tuple[str, str], str] = {}
    uid_global: Dict[str, Set[str]] = {}
    for (host_key, uid_token), names in candidates.items():
        if len(names) == 1:
            name = next(iter(names))
            exact_map[(host_key, uid_token)] = name
            uid_global.setdefault(uid_token, set()).add(name)

    unambiguous_global = {
        uid_token: next(iter(names))
        for uid_token, names in uid_global.items()
        if len(names) == 1
    }
    return exact_map, unambiguous_global


def _resolve_uid_user(
    user_val: Any,
    host_val: str | None,
    exact_map: Dict[Tuple[str, str], str],
    global_map: Dict[str, str],
) -> Any:
    if not user_val:
        return user_val
    raw = str(user_val).strip()
    if not _UID_TOKEN_RE.match(raw):
        return user_val
    uid_key = raw.casefold()
    host_key = (host_val or "").casefold()
    if (host_key, uid_key) in exact_map:
        return exact_map[(host_key, uid_key)]
    if not host_key and uid_key in global_map:
        return global_map[uid_key]
    return raw


def _extract_created_accounts(
    extracted_events: List[Dict[str, Any]],
    findings: List[Dict[str, Any]] | None,
) -> Dict[str, float | None]:
    """Return earliest creation timestamp (or None) for accounts created in logs/findings."""
    created: Dict[str, float | None] = {}

    def _record(acct: Any, ts_sec: float | None) -> None:
        key = norm_user(acct)
        if not key or is_process_or_command_name(acct) or _UID_TOKEN_RE.match(str(acct)):
            return
        prev = created.get(key)
        if key not in created or (ts_sec is not None and (prev is None or ts_sec < prev)):
            created[key] = ts_sec

    for evt in extracted_events:
        ts_sec = _parse_ts_seconds(evt.get("timestamp") or "")
        for text in (evt.get("action") or "", evt.get("raw_message") or "", evt.get("command_line") or ""):
            m_auth = _USERADD_AUTH_RE.search(text)
            if m_auth:
                _record(m_auth.group(1), ts_sec)
            m_cmd = _USERADD_CMD_RE.search(text.strip())
            if m_cmd:
                _record(m_cmd.group(1), ts_sec)

    if findings:
        for f in findings:
            rule_id = str(f.get("rule_id") or "").lower()
            tech = str(f.get("mitre_technique") or "").upper()
            if "useradd" in rule_id or tech.startswith("T1136"):
                ri = f.get("rule_information") or {}
                for cand in (f.get("user"), *(f.get("users") or []), *(ri.get("users") or [])):
                    if cand and str(cand).lower() not in {"root", "unknown", "-"}:
                        _record(cand, None)

    return created


def _is_ssh_success_event(evt: Dict[str, Any]) -> bool:
    ev_type = (evt.get("event_type") or "").casefold()
    if ev_type == "ssh_success":
        return True
    text = f"{evt.get('action') or ''} {evt.get('raw_message') or ''}".lower()
    return ("sshd" in text or "ssh" in text) and ("accepted " in text or "ssh_success" in text)


def _valid_external_ip(cand: Any) -> str | None:
    s = str(cand or "").strip()
    if s and _is_ip_address(s) and not is_private_ip(s):
        return s
    return None


def _select_primary_ip_role(roles_set: Set[str], is_adversary_default: bool = False) -> str:
    has_attack_or_c2 = bool(roles_set & {"attack_source", "c2"})
    if "mining_pool" in roles_set and not has_attack_or_c2:
        return "mining_pool"
    if "payload_host" in roles_set and not has_attack_or_c2:
        return "payload_host"
    if "exfil_destination" in roles_set and not has_attack_or_c2:
        return "exfil_destination"
    if "c2" in roles_set and "attack_source" not in roles_set:
        return "c2"
    if roles_set or is_adversary_default:
        return "adversary_infrastructure"
    return "external_ip"


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

    # B2 Pass 1: Build IP-to-host alias map purely from explicit evidence bindings.
    ambiguous_ips: Set[str] = set()
    ip_to_host = build_host_alias_map(events, ambiguous_ips=ambiguous_ips)
    host_aliases_lookup: Dict[str, List[str]] = {}
    for alias_ip, alias_host in ip_to_host.items():
        host_aliases_lookup.setdefault(alias_host, []).append(alias_ip)
    for alias_list in host_aliases_lookup.values():
        alias_list.sort()

    for evt in extracted_events:
        if evt.get("host") and evt["host"] in ip_to_host:
            evt["host"] = ip_to_host[evt["host"]]

    # Single-host evidence fallback (e.g. hostless auditd logs when the case has one host)
    known_non_ip_hosts = {
        evt["host"]
        for evt in extracted_events
        if evt.get("host") and not _is_ip_address(evt["host"])
    }
    single_host = next(iter(known_non_ip_hosts)) if len(known_non_ip_hosts) == 1 else None
    if single_host:
        for evt in extracted_events:
            if not evt.get("host") and not evt.get("workstation"):
                evt["host"] = single_host

    # Evidence-derived uid -> account mapping (sudo/auth/useradd logs only)
    uid_exact_map, uid_global_map = _extract_uid_account_map(extracted_events)
    for evt in extracted_events:
        if evt.get("user"):
            evt["user"] = _resolve_uid_user(evt["user"], evt.get("host"), uid_exact_map, uid_global_map)

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

    # Mark SSH logins by accounts created earlier in the timeline as attack-path activity
    created_accounts = _extract_created_accounts(extracted_events, findings)
    for evt in extracted_events:
        if evt.get("user") and _is_ssh_success_event(evt):
            u_key = norm_user(evt["user"])
            if u_key and u_key in created_accounts:
                create_ts = created_accounts[u_key]
                login_ts = _parse_ts_seconds(evt.get("timestamp") or "")
                if create_ts is None or login_ts is None or login_ts >= create_ts:
                    evt["is_attack_path"] = True

    events_by_id: Dict[str, Dict[str, Any]] = {
        evt["id"]: evt for evt in extracted_events if evt.get("id")
    }

    # B3: Determine adversary infrastructure, IP roles, compromised hosts, accounts, and finding edges
    adversary_ips: Set[str] = set()
    compromised_hosts: Set[str] = set()
    ip_infra_roles: Dict[str, Set[str]] = {}
    finding_edges: List[Tuple[str, str, str, str]] = []  # (src_id, tgt_id, tactic, evt_id)
    finding_users: List[Tuple[str, str | None]] = []

    if findings:
        for f in findings:
            ri = f.get("rule_information") or {}
            tactic = str(f.get("mitre_tactic") or ri.get("tactic") or "Activity").strip()
            rule_id = str(f.get("rule_id") or "").lower()
            tech = str(f.get("mitre_technique") or "").upper()
            infra_hint = str(ri.get("infrastructure_role") or "").lower()

            role = f.get("actor_role") or ""
            actor = f.get("actor") or ""
            if role == "adversary_infrastructure" and actor:
                adversary_ips.add(str(actor))

            target_role = f.get("target_role") or ""
            target_candidates: List[str] = []
            for raw_t in (
                f.get("target_host"),
                f.get("host"),
                *(f.get("hosts") or []),
                *(ri.get("hosts") or []),
            ):
                if not raw_t:
                    continue
                resolved_t = ip_to_host.get(str(raw_t), str(raw_t))
                if is_valid_host_name(resolved_t) and not _is_ip_address(resolved_t):
                    if resolved_t not in target_candidates:
                        target_candidates.append(resolved_t)
            if not target_candidates and single_host:
                target_candidates = [single_host]
            if target_role == "compromised_host" or tactic in {
                "Reconnaissance", "Initial Access", "Execution", "Persistence",
                "Privilege Escalation", "Defense Evasion", "Command and Control",
                "Exfiltration", "Impact",
            }:
                for th in target_candidates:
                    compromised_hosts.add(th)

            # Collect accounts named in findings or matched events
            primary_target_host = target_candidates[0] if target_candidates else single_host
            raw_finding_users: List[Any] = [
                f.get("user"),
                *(f.get("users") or []),
                *(ri.get("users") or []),
            ]
            if role == "compromised_account" and actor:
                raw_finding_users.append(actor)
            for eid in f.get("matching_event_ids") or []:
                ev_obj = events_by_id.get(str(eid))
                if ev_obj and ev_obj.get("user"):
                    raw_finding_users.append(ev_obj["user"])
            for raw_u in raw_finding_users:
                if not raw_u:
                    continue
                resolved_u = _resolve_uid_user(raw_u, primary_target_host, uid_exact_map, uid_global_map)
                if (
                    resolved_u
                    and str(resolved_u).upper() not in {"SYSTEM", "UNKNOWN", "-"}
                    and not is_process_or_command_name(resolved_u)
                ):
                    finding_users.append((str(resolved_u), primary_target_host))

            # Collect outbound destination IPs by role first so dst IPs are not treated as inbound sources
            outbound_role_ips: List[Tuple[str, str]] = []
            matched_evts = [events_by_id[str(eid)] for eid in (f.get("matching_event_ids") or []) if str(eid) in events_by_id]

            is_mining_finding = (
                "miner" in rule_id or tech.startswith("T1496") or tactic == "Impact" or "mining" in infra_hint
            )
            is_payload_finding = (
                "tmp-download" in rule_id or tech.startswith("T1105") or "payload" in infra_hint
            )
            is_exfil_finding = (
                tactic == "Exfiltration" or "exfil" in rule_id or "scp-transfer" in rule_id or "exfil" in infra_hint
            )
            is_c2_finding = (
                "reverse-shell" in rule_id or "c2" in infra_hint or (tactic == "Command and Control" and not is_payload_finding)
            )

            def _add_out_ip(ip_cand: Any, rtag: str) -> None:
                ext = _valid_external_ip(ip_cand)
                if ext and (ext, rtag) not in outbound_role_ips:
                    outbound_role_ips.append((ext, rtag))

            if is_mining_finding:
                for cand in (
                    f.get("dst_ip"),
                    ri.get("dst_ip"),
                    ri.get("destination_ip"),
                    *(ri.get("destination_ips") or []),
                    actor if actor and not (f.get("src_ip") or f.get("source_ips")) else None,
                ):
                    _add_out_ip(cand, "mining_pool")
                for ev_m in matched_evts:
                    _add_out_ip(ev_m.get("dst_ip"), "mining_pool")
                    for ip_m in _IP_RE.findall(ev_m.get("command_line") or ""):
                        _add_out_ip(ip_m, "mining_pool")

            if is_payload_finding:
                for text_val in (
                    f.get("description") or "",
                    str(ri.get("payload_url") or ""),
                    str(ri.get("url") or ""),
                    *[f"{ev_m.get('command_line') or ''} {ev_m.get('action') or ''}" for ev_m in matched_evts],
                ):
                    for host_m in _URL_HOST_RE.findall(str(text_val)):
                        _add_out_ip(host_m, "payload_host")
                for cand in (f.get("dst_ip"), ri.get("dst_ip"), ri.get("destination_ip"), *(ri.get("destination_ips") or [])):
                    _add_out_ip(cand, "payload_host")
                for ev_m in matched_evts:
                    _add_out_ip(ev_m.get("dst_ip"), "payload_host")

            if is_exfil_finding:
                for cand in (
                    f.get("dst_ip"),
                    ri.get("dst_ip"),
                    ri.get("destination_ip"),
                    *(ri.get("destination_ips") or []),
                ):
                    _add_out_ip(cand, "exfil_destination")
                for ev_m in matched_evts:
                    _add_out_ip(ev_m.get("dst_ip"), "exfil_destination")
                    for ip_m in _IP_RE.findall(ev_m.get("command_line") or ""):
                        _add_out_ip(ip_m, "exfil_destination")

            if is_c2_finding:
                for cand in (
                    f.get("dst_ip"),
                    ri.get("dst_ip"),
                    ri.get("destination_ip"),
                    *(ri.get("destination_ips") or []),
                ):
                    _add_out_ip(cand, "c2")
                for ev_m in matched_evts:
                    _add_out_ip(ev_m.get("dst_ip"), "c2")
                    for ip_m in _DEV_TCP_RE.findall(f"{ev_m.get('command_line') or ''} {ev_m.get('action') or ''}"):
                        _add_out_ip(ip_m, "c2")

            outbound_ip_set = {ip_val for ip_val, _ in outbound_role_ips}
            for ext_ip, rtag in outbound_role_ips:
                ip_infra_roles.setdefault(ext_ip, set()).add(rtag)
                for th in target_candidates:
                    finding_edges.append((f"host-{th}", f"ip-{ext_ip}", tactic, ""))

            # Requirement 1: for each finding with a source IP and target host, add edge source -> host labelled with tactic
            raw_inbound_src_ips: List[str] = []
            for cand in (
                f.get("src_ip"),
                *(f.get("source_ips") or []),
                ri.get("src_ip"),
                *(ri.get("src_ips") or []),
                *(ri.get("source_ips") or []),
            ):
                s = str(cand or "").strip()
                if s and _is_ip_address(s) and s not in raw_inbound_src_ips:
                    raw_inbound_src_ips.append(s)
            inbound_src_ips = strip_target_alias_ips(raw_inbound_src_ips, target_candidates, ip_to_host)
            victim_alias_set = host_alias_ips(target_candidates, ip_to_host)
            if (
                not inbound_src_ips
                and role == "adversary_infrastructure"
                and actor
                and _is_ip_address(str(actor))
                and str(actor) not in outbound_ip_set
                and str(actor) not in victim_alias_set
                and tactic in {"Reconnaissance", "Initial Access", "Persistence", "Credential Access"}
            ):
                inbound_src_ips.append(str(actor))

            for src_ip in inbound_src_ips:
                src_node_id = f"host-{ip_to_host[src_ip]}" if src_ip in ip_to_host else f"ip-{src_ip}"
                if not is_private_ip(src_ip):
                    ip_infra_roles.setdefault(src_ip, set()).add(
                        "c2" if tactic == "Command and Control" else "attack_source"
                    )
                for th in target_candidates:
                    tgt_node_id = f"host-{th}"
                    if src_node_id != tgt_node_id:
                        finding_edges.append((src_node_id, tgt_node_id, tactic, ""))

    def _attach_process_attrs(node: Dict[str, Any], proc: str | None, cmd: str | None) -> None:
        if not proc and not cmd:
            return
        node_details = node.setdefault("details", {})
        if proc:
            procs = node_details.setdefault("processes", [])
            if proc not in procs:
                procs.append(proc)
        if cmd:
            cmds = node_details.setdefault("commands", [])
            if cmd not in cmds:
                cmds.append(cmd)

    def _ensure_host_node(host_name: str, *, is_attack: bool, ts: str = "", evt_id: str = "") -> str:
        h_id = f"host-{host_name}"
        is_compromised_by_finding = host_name in compromised_hosts
        known_aliases = host_aliases_lookup.get(host_name) or []
        if h_id not in nodes_map:
            nodes_map[h_id] = {
                "id": h_id,
                "label": host_name,
                "type": "host",
                "role": "compromised_host" if is_compromised_by_finding else "internal_host",
                "is_compromised": is_compromised_by_finding,
                "is_attack_path": is_attack or is_compromised_by_finding,
                "event_count": 1 if evt_id else 0,
                "event_ids": [evt_id] if evt_id else [],
                "first_seen": ts,
                "last_seen": ts,
            }
            if known_aliases:
                nodes_map[h_id]["details"] = {"aliases": list(known_aliases)}
        else:
            if evt_id:
                nodes_map[h_id]["event_count"] += 1
                if evt_id not in nodes_map[h_id]["event_ids"]:
                    nodes_map[h_id]["event_ids"].append(evt_id)
            if is_compromised_by_finding:
                nodes_map[h_id]["is_compromised"] = True
                nodes_map[h_id]["role"] = "compromised_host"
            if is_attack or is_compromised_by_finding:
                nodes_map[h_id]["is_attack_path"] = True
            if ts:
                if not nodes_map[h_id].get("first_seen"):
                    nodes_map[h_id]["first_seen"] = ts
                nodes_map[h_id]["last_seen"] = ts
            if known_aliases:
                nodes_map[h_id].setdefault("details", {})["aliases"] = list(known_aliases)
        return h_id

    def _ensure_ip_node(ip_addr: str, *, is_attack: bool, ts: str = "", evt_id: str = "") -> str:
        node_id = f"ip-{ip_addr}"
        is_priv = is_private_ip(ip_addr)
        is_ambiguous = ip_addr in ambiguous_ips
        roles_set = ip_infra_roles.get(ip_addr, set())
        is_adversary = bool(roles_set) or (ip_addr in adversary_ips)
        node_role = (
            "internal_host"
            if is_priv and not is_adversary
            else _select_primary_ip_role(roles_set, is_adversary_default=(ip_addr in adversary_ips))
        )
        if node_id not in nodes_map:
            nodes_map[node_id] = {
                "id": node_id,
                "label": ip_addr,
                "type": "ip",
                "role": node_role,
                "is_compromised": is_adversary,
                "is_attack_path": is_attack or is_adversary,
                "event_count": 1 if evt_id else 0,
                "event_ids": [evt_id] if evt_id else [],
                "first_seen": ts,
                "last_seen": ts,
            }
            if is_ambiguous:
                nodes_map[node_id]["ambiguous"] = True
        else:
            if evt_id:
                nodes_map[node_id]["event_count"] += 1
                if evt_id not in nodes_map[node_id]["event_ids"]:
                    nodes_map[node_id]["event_ids"].append(evt_id)
            if is_adversary:
                nodes_map[node_id]["is_compromised"] = True
                nodes_map[node_id]["role"] = node_role
                nodes_map[node_id]["is_attack_path"] = True
            if is_attack:
                nodes_map[node_id]["is_attack_path"] = True
            if ts:
                if not nodes_map[node_id].get("first_seen"):
                    nodes_map[node_id]["first_seen"] = ts
                nodes_map[node_id]["last_seen"] = ts
            if is_ambiguous:
                nodes_map[node_id]["ambiguous"] = True
        if roles_set:
            node_details = nodes_map[node_id].setdefault("details", {})
            node_details["infrastructure_roles"] = sorted(roles_set)
        return node_id

    def _ensure_user_node(raw_user: str, *, is_attack: bool, ts: str = "", evt_id: str = "") -> str:
        identity = norm_user(raw_user) or str(raw_user).casefold()
        display_user = format_user(raw_user)
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
                "event_count": 1 if evt_id else 0,
                "event_ids": [evt_id] if evt_id else [],
                "first_seen": ts,
                "last_seen": ts,
            }
        else:
            if evt_id:
                nodes_map[u_id]["event_count"] += 1
                if evt_id not in nodes_map[u_id]["event_ids"]:
                    nodes_map[u_id]["event_ids"].append(evt_id)
            if is_attack:
                nodes_map[u_id]["is_compromised"] = True
                nodes_map[u_id]["is_attack_path"] = True
        return u_id

    def _upsert_finding_edge(src_id: str, tgt_id: str, tactic_label: str) -> None:
        edge_key = (src_id, tgt_id)
        existing = edges_map.get(edge_key)
        if not existing:
            edges_map[edge_key] = {
                "id": f"edge-{src_id}-{tgt_id}",
                "source": src_id,
                "target": tgt_id,
                "label": tactic_label,
                "_tactics": [tactic_label] if tactic_label else [],
                "count": 1,
                "event_ids": [],
                "is_attack_path": True,
            }
        else:
            existing["is_attack_path"] = True
            tactics_list = existing.setdefault("_tactics", [])
            if tactic_label and tactic_label not in tactics_list:
                tactics_list.append(tactic_label)
                existing["label"] = ", ".join(tactics_list)

    # Pass 2: Create nodes and aggregate edges (only host, ip, and user nodes)
    for evt in extracted_events:
        is_attack = evt["is_attack_path"]
        ts = evt["timestamp"]
        evt_id = evt["id"]
        proc = evt.get("process")
        cmdline = evt.get("command_line")

        # Resolve host (merge private IP into host if evidence-derived mapping exists)
        effective_host = evt["host"]
        if effective_host and _is_ip_address(effective_host):
            effective_host = ip_to_host.get(effective_host) if is_private_ip(effective_host) else None
        if effective_host is None and evt["workstation"] and not _is_ip_address(evt["workstation"]):
            effective_host = evt["workstation"]
        if not effective_host and evt["src_ip"] and evt["src_ip"] in ip_to_host:
            effective_host = ip_to_host[evt["src_ip"]]
        if effective_host and not is_valid_host_name(effective_host):
            effective_host = None

        # 1. Host Node — only mark compromised if findings confirm it (B3)
        if effective_host:
            h_id = _ensure_host_node(effective_host, is_attack=is_attack, ts=ts, evt_id=evt_id)
            _attach_process_attrs(nodes_map[h_id], proc, cmdline)

        # 2. User Node
        if evt["user"]:
            u_id = _ensure_user_node(evt["user"], is_attack=is_attack, ts=ts, evt_id=evt_id)
            _attach_process_attrs(nodes_map[u_id], proc, cmdline)

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
                src_node_id = _ensure_host_node(ip_to_host[src_ip], is_attack=is_attack, ts=ts, evt_id=evt_id)
            else:
                src_node_id = _ensure_ip_node(src_ip, is_attack=is_attack, ts=ts, evt_id=evt_id)

        # 4. Destination IP
        dst_ip = evt["dst_ip"]
        dst_node_id = None
        if dst_ip:
            if dst_ip in ip_to_host:
                dst_node_id = _ensure_host_node(ip_to_host[dst_ip], is_attack=is_attack, ts=ts, evt_id=evt_id)
            else:
                dst_node_id = _ensure_ip_node(dst_ip, is_attack=is_attack, ts=ts, evt_id=evt_id)

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

    # Ensure finding accounts, external IP roles, and directional tactic edges are materialized
    for raw_u, host_name in finding_users:
        u_id = _ensure_user_node(raw_u, is_attack=True)
        if host_name:
            h_id = _ensure_host_node(host_name, is_attack=True)
            edge_key = (u_id, h_id)
            if edge_key not in edges_map:
                edges_map[edge_key] = {
                    "id": f"edge-{u_id}-{h_id}",
                    "source": u_id,
                    "target": h_id,
                    "label": "Finding Activity",
                    "count": 1,
                    "event_ids": [],
                    "is_attack_path": True,
                }
            else:
                edges_map[edge_key]["is_attack_path"] = True

    for src_id, tgt_id, tactic_label, _ in finding_edges:
        if src_id.startswith("ip-"):
            _ensure_ip_node(src_id[3:], is_attack=True)
        elif src_id.startswith("host-"):
            _ensure_host_node(src_id[5:], is_attack=True)
        if tgt_id.startswith("ip-"):
            _ensure_ip_node(tgt_id[3:], is_attack=True)
        elif tgt_id.startswith("host-"):
            _ensure_host_node(tgt_id[5:], is_attack=True)
        _upsert_finding_edge(src_id, tgt_id, tactic_label)

    for e in edges_map.values():
        e.pop("_tactics", None)

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
