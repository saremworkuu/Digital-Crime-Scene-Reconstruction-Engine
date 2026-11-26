"""Shared, evidence-led entity classification helpers."""
import ipaddress
import os
from typing import Any, Iterable


_INVALID_HOST_PLACEHOLDERS = {"", "-", "unknown", "unknown_host"}

# Unambiguous binary/command names that must never become graph user/COMP nodes
# even if legacy or raw events place them in a user field.
_KNOWN_COMMAND_NAMES = {
    "bash", "sh", "zsh", "dash", "csh", "ksh",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh",
    "kworkerd", "xmrig", "minerd",
    "mysqldump", "mysqld", "psql", "sqlite3",
    "crontab", "useradd", "usermod", "userdel", "groupadd", "passwd", "chpasswd",
    "scp", "sftp", "rsync", "ftp", "tftp",
    "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet",
    "python", "python2", "python3", "perl", "ruby", "php", "node", "awk", "sed",
    "vim", "vi", "nano", "cat", "ls", "id", "whoami", "uname", "ps", "top", "ss", "netstat",
    "chmod", "chown", "rm", "cp", "mv", "mkdir", "touch", "tar", "gzip", "gunzip", "unzip",
    "sudo", "su", "sshd", "httpd", "apache2", "nginx",
    "vssadmin", "vssadmin.exe", "procdump", "procdump.exe", "procdump64.exe",
    "psexec", "psexec.exe", "mimikatz", "rclone", "adfind", "adfind.exe",
}


def is_numeric_host(value: Any) -> bool:
    """Return True if *value* is non-empty and consists solely of ASCII digits."""
    s = str(value or "").strip()
    return bool(s) and s.isascii() and s.isdigit()


def is_valid_host_name(value: Any) -> bool:
    """Return True if *value* is a non-placeholder, non-numeric host name."""
    s = str(value or "").strip()
    if s.casefold() in _INVALID_HOST_PLACEHOLDERS:
        return False
    if is_numeric_host(s):
        return False
    return True


def _executable_basename(value: Any) -> str:
    raw = str(value or "").strip().strip('"\'')
    if not raw:
        return ""
    return os.path.basename(raw.replace("\\", "/")).casefold()


def is_process_or_command_name(
    value: Any,
    *,
    process_name: Any = None,
    command_line: Any = None,
) -> bool:
    """Return True when a candidate user/entity value is actually a process or command."""
    s = str(value or "").strip()
    if not s or s.casefold() in {"-", "unknown"}:
        return False

    lower = s.casefold()

    # Path-like executables (e.g. /usr/bin/mysqldump) are commands, not account names.
    if "/" in s:
        return True

    # Multi-token strings with CLI flags/paths (e.g. "kworkerd --pool ...") are commands.
    if " " in s and (" -" in s or " /" in s or ".exe" in lower):
        return True

    # Strip optional domain prefix only to avoid misclassifying DOMAIN\user; if a
    # Windows domain account exists, keep it unless it explicitly matches the process.
    bare = lower.split("\\", 1)[-1]
    if bare in _KNOWN_COMMAND_NAMES:
        return True

    proc_base = _executable_basename(process_name)
    if proc_base and bare in {proc_base, proc_base.removesuffix(".exe")}:
        return True

    cmd_str = str(command_line or "").strip()
    if cmd_str:
        argv0 = _executable_basename(cmd_str.split()[0])
        if argv0 and bare in {argv0, argv0.removesuffix(".exe")}:
            return True

    return False


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


def is_ip_address(value: Any) -> bool:
    """Return True if *value* parses as a valid IPv4 or IPv6 address."""
    s = str(value or "").strip()
    if not s:
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _event_mapping_view(item: Any) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Return (top_level_dict, details_dict, extra_dict) for an Event ORM row or dict."""
    if isinstance(item, dict):
        top = item
        details = item.get("details") if isinstance(item.get("details"), dict) else item
        raw_extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        det_extra = details.get("extra") if isinstance(details.get("extra"), dict) else {}
        extra = {**raw_extra, **det_extra}
        return top, details, extra
    details = getattr(item, "details", None)
    details = details if isinstance(details, dict) else {}
    extra = details.get("extra") if isinstance(details.get("extra"), dict) else {}
    top = {
        "event_type": getattr(item, "event_type", None),
        "source": getattr(item, "source", None),
    }
    return top, details, extra


_VULN_OR_INVENTORY_TYPES = {
    "vuln_scan",
    "vulnerability_scan",
    "vulnerability_finding",
    "host_info",
    "asset",
    "host_inventory",
    "system_info",
}

_NETFLOW_PCAP_TYPES = {
    "network_connection",
    "network_flow",
    "netflow",
    "flow",
    "pcap",
}

_WAF_OR_WEB_ALERT_TYPES = {
    "waf",
    "waf_alert",
    "web_access",
    "web_log",
    "http",
}


def is_netflow_pcap_or_waf(item: Any) -> bool:
    """Return True if *item* is a NetFlow, PCAP, or WAF event/record."""
    top, details, extra = _event_mapping_view(item)
    ev_type = str(top.get("event_type") or details.get("event_type") or "").strip().lower()
    src = str(top.get("source") or details.get("source") or extra.get("source") or "").strip().lower()
    src_file = str(top.get("source_file") or details.get("source_file") or "").strip().lower()

    if ev_type in _NETFLOW_PCAP_TYPES or ev_type in _WAF_OR_WEB_ALERT_TYPES:
        return True
    if any(tok in src for tok in ("netflow", "pcap", "waf")) or any(
        tok in src_file for tok in ("netflow", "pcap", "waf")
    ):
        return True
    if ev_type == "edr_alert" or "rule" in extra or "rule_id" in details or "rule_id" in top:
        has_http_shape = any(
            details.get(k) or extra.get(k) or top.get(k)
            for k in ("uri", "request_uri", "url", "http_method", "user_agent")
        )
        if has_http_shape:
            return True
    return False


def build_host_alias_map(
    events: Iterable[Any],
    *,
    ambiguous_ips: set[str] | None = None,
) -> dict[str, str]:
    """Build an unambiguous IP -> canonical host map from explicit evidence bindings.

    Extracts pairings from records that carry both a non-IP host name and an IP
    belonging to that host (e.g. vulnerability scan host_ip/extra.host_ip,
    asset/host_info records, or Windows WorkstationName + internal src_ip).
    """
    ip_host_candidates: dict[str, dict[str, int]] = {}

    def _add_candidate(ip_val: Any, host_val: Any, weight: int) -> None:
        ip_s = str(ip_val or "").strip()
        h_s = str(host_val or "").strip()
        if not ip_s or not is_ip_address(ip_s):
            return
        if not h_s or not is_valid_host_name(h_s) or is_ip_address(h_s):
            return
        buckets = ip_host_candidates.setdefault(ip_s, {})
        buckets[h_s] = buckets.get(h_s, 0) + weight

    for item in events:
        top, details, extra = _event_mapping_view(item)
        ev_type = str(top.get("event_type") or details.get("event_type") or "").strip().lower()
        host_inferred = details.get("host_inferred")
        if host_inferred is None:
            host_inferred = top.get("host_inferred")

        host_name = None
        if not host_inferred:
            for cand in (
                details.get("host"),
                details.get("computer"),
                details.get("Computer"),
                details.get("hostname"),
                details.get("host_name"),
                extra.get("hostname"),
                extra.get("host_name"),
                top.get("host"),
                top.get("computer"),
                top.get("Computer"),
                top.get("hostname"),
            ):
                if cand and is_valid_host_name(cand) and not is_ip_address(cand):
                    host_name = str(cand).strip()
                    break

        if host_name:
            ip_keys = ("host_ip", "local_ip", "server_ip", "asset_ip", "victim_ip", "host_address")
            if ev_type in _VULN_OR_INVENTORY_TYPES:
                ip_keys = (*ip_keys, "ip", "ip_address", "address")
            for k in ip_keys:
                for src_map in (details, extra, top):
                    if src_map.get(k):
                        _add_candidate(src_map.get(k), host_name, 10)

        ws = (
            details.get("WorkstationName")
            or extra.get("WorkstationName")
            or top.get("WorkstationName")
        )
        ws_ip = (
            details.get("src_ip")
            or details.get("source_ip")
            or details.get("IpAddress")
            or extra.get("IpAddress")
            or top.get("src_ip")
            or top.get("source_ip")
        )
        if ws and ws_ip and is_internal_ip(str(ws_ip)):
            _add_candidate(ws_ip, ws, 4)

    alias_map: dict[str, str] = {}
    for ip, candidates in ip_host_candidates.items():
        if len({host.casefold() for host in candidates}) > 1:
            if ambiguous_ips is not None:
                ambiguous_ips.add(ip)
            continue
        best = max(candidates.values())
        winners = [host for host, score in candidates.items() if score == best]
        if len(winners) == 1:
            alias_map[ip] = winners[0]
    return alias_map


def resolve_host_alias(value: Any, alias_map: dict[str, str]) -> str | None:
    """Resolve an IP alias to its host name, or return a valid non-IP host name."""
    s = str(value or "").strip()
    if not s:
        return None
    if s in alias_map:
        return alias_map[s]
    if is_valid_host_name(s) and not is_ip_address(s):
        return s
    return None


def resolve_endpoint_alias(item: Any, alias_map: dict[str, str]) -> str | None:
    """Return alias host when either src_ip or dst_ip endpoint on *item* is an alias."""
    if not alias_map:
        return None
    top, details, extra = _event_mapping_view(item)
    src_ip = str(
        details.get("src_ip")
        or details.get("source_ip")
        or details.get("SourceIp")
        or top.get("src_ip")
        or top.get("source_ip")
        or extra.get("src_ip")
        or ""
    ).strip()
    dst_ip = str(
        details.get("dst_ip")
        or details.get("destination_ip")
        or details.get("DestinationIp")
        or top.get("dst_ip")
        or top.get("destination_ip")
        or extra.get("dst_ip")
        or ""
    ).strip()
    if src_ip and src_ip in alias_map:
        return alias_map[src_ip]
    if dst_ip and dst_ip in alias_map:
        return alias_map[dst_ip]
    return None


def host_alias_ips(hosts: Iterable[Any], alias_map: dict[str, str]) -> set[str]:
    """Return all alias IPs belonging to any host in *hosts* (case-insensitive)."""
    host_cfs: set[str] = set()
    for h in hosts:
        resolved = resolve_host_alias(h, alias_map) or str(h or "").strip()
        if resolved and is_valid_host_name(resolved) and not is_ip_address(resolved):
            host_cfs.add(resolved.casefold())
    if not host_cfs or not alias_map:
        return set()
    return {
        ip
        for ip, alias_host in alias_map.items()
        if alias_host.casefold() in host_cfs
    }


def strip_target_alias_ips(
    ips: Iterable[Any],
    target_hosts: Iterable[Any],
    alias_map: dict[str, str],
) -> list[str]:
    """Filter out any alias IP of the finding's target host(s) while preserving order."""
    victim_aliases = host_alias_ips(target_hosts, alias_map)
    result: list[str] = []
    seen: set[str] = set()
    for val in ips:
        s = str(val or "").strip()
        if not s or s.casefold() in {"unknown", "unknown_host", "-"}:
            continue
        if s in victim_aliases:
            continue
        if s not in seen:
            seen.add(s)
            result.append(s)
    return result


def infrastructure_role(*, tactic: str = "", field_role: str = "") -> str | None:
    """Map explicit finding context to a display role; no traffic-only claims."""
    role = (field_role or "").strip().lower()
    if role in {"mining_pool", "mining pool", "miner_pool"} or tactic == "Impact":
        return "Mining Pool"
    if role in {"c2", "command_and_control", "command and control"} or tactic == "Command and Control":
        return "C2"
    if role in {"payload", "payload_source", "payload_host"}:
        return "Payload"
    if tactic == "Initial Access":
        return "Payload"
    if role in {"exfiltration", "exfil", "exfiltration_destination", "exfil_destination"} or tactic == "Exfiltration":
        return "Exfiltration"
    if role in {"attack_source", "source", "attacker"}:
        return "Attack Source"
    if tactic in {"Credential Access", "Reconnaissance"}:
        return "Attack Source"
    return None
