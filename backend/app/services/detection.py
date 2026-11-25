
from collections import defaultdict, deque
from datetime import timedelta
from datetime import datetime
import re
from urllib.parse import unquote_plus

from app.services.rule_loader import load_rule
from app.services.entity_classification import is_internal_ip


def _event_fields(event):
    details = getattr(event, "details", None) or (event.get("details", {}) if isinstance(event, dict) else {}) or {}
    get = (lambda key, default=None: event.get(key, default)) if isinstance(event, dict) else (lambda key, default=None: getattr(event, key, default))
    timestamp = get("timestamp")
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            timestamp = None
    return details, timestamp, str(get("id", ""))


def _is_ip_address(value) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def detect_macro_attachment_delivery(events):
    """Detect delivered macro documents or script-bearing archives (T1566.001)."""
    macro_ext = (".docm", ".xlsm", ".pptm")
    script_ext = (".js", ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".wsf")
    findings = []
    for event in events:
        details, _, event_id = _event_fields(event)
        extra = details.get("extra") if isinstance(details.get("extra"), dict) else {}
        text = " ".join(str(details.get(k, "")) for k in ("message", "description", "action", "attachment", "filename", "attachments")) + " " + " ".join(str(extra.get(k, "")) for k in ("subject", "attachment", "status", "to", "from"))
        text = text.lower()
        files = [str(details.get(k, "")) for k in ("attachment", "filename", "attachments") if details.get(k)] + [str(extra.get("attachment"))] if extra.get("attachment") else [str(details.get(k, "")) for k in ("attachment", "filename", "attachments") if details.get(k)]
        delivered = any(word in text for word in ("delivered", "delivery", "received", "mailbox", "inbound"))
        has_attachment = any(name.lower().endswith(macro_ext) for name in files) or (any(x in text for x in macro_ext))
        archive = any(name.lower().endswith((".zip", ".7z", ".rar")) for name in files) or any(x in text for x in (".zip", ".7z", ".rar"))
        has_script = any(name.lower().endswith(script_ext) for name in files) or any(x in text for x in script_ext)
        recipient = details.get("recipient") or details.get("user") or details.get("username") or details.get("to") or extra.get("to")
        if not event_id or not delivered or not recipient or not (has_attachment or (archive and has_script)):
            continue
        findings.append({"rule_id": "mail_macro_attachment", "rule_name": "Macro-Enabled or Script Archive Delivered", "severity": "high", "mitre_technique": "T1566.001", "mitre_tactic": "Initial Access", "description": "A delivered email to a user contains a macro-enabled attachment or an archive referencing a script; execution is not established.", "user": str(recipient), "matching_event_ids": [event_id], "rule_information": {"tactic": "Initial Access", "attachment_names": files}})
    return findings


def detect_smb_lateral_movement(events, window_seconds: int = 60, min_targets: int = 3):
    """Detect short-window SMB/admin-share movement across distinct hosts."""
    records = []
    for event in events:
        details, ts, event_id = _event_fields(event)
        if not ts or not event_id:
            continue
        port = str(details.get("destination_port") or details.get("dst_port") or "")
        share = str(details.get("share") or details.get("path") or details.get("message") or "").lower()
        logon_type = str(details.get("logon_type") or details.get("LogonType") or "")
        is_smb = port in ("445", "139") or any(x in share for x in ("admin$", "ipc$", "c$"))
        is_type3 = logon_type == "3" and (details.get("source_host") or details.get("workstation") or details.get("WorkstationName"))
        if not (is_smb or is_type3):
            continue
        src = details.get("source_host") or details.get("src_host") or details.get("workstation") or details.get("WorkstationName") or details.get("source_ip") or details.get("src_ip")
        dst = details.get("target_host") or details.get("dest_host") or details.get("destination_host") or details.get("host") or details.get("Computer")
        if src and _is_ip_address(src) and not is_internal_ip(str(src)):
            continue
        if dst and _is_ip_address(dst) and not is_internal_ip(str(dst)):
            continue
        if src and dst and str(src).casefold() != str(dst).casefold():
            records.append((ts, str(src), str(dst), event_id, event))
    findings = []
    for ts, src, _, _, _ in records:
        window = [r for r in records if r[1] == src and abs((r[0] - ts).total_seconds()) <= window_seconds]
        targets = {r[2] for r in window}
        if len(targets) >= min_targets:
            ids = sorted({r[3] for r in window})
            if not any(f["matching_event_ids"] == ids for f in findings):
                findings.append({"rule_id": "smb_lateral_movement", "rule_name": "SMB or Remote Logon Lateral Movement", "severity": "high", "mitre_technique": "T1021.002", "mitre_tactic": "Lateral Movement", "description": f"SMB/admin-share or type 3 logon activity from {src} reached {len(targets)} distinct internal targets within {window_seconds} seconds.", "host": src, "target_host": src, "matching_event_ids": ids, "rule_information": {"tactic": "Lateral Movement", "source_host": src, "target_hosts": sorted(targets)}})
    return findings


def detect_periodic_beaconing(events, minimum_connections: int = 4, tolerance_seconds: float = 5.0):
    """Detect periodic connections to a repeated external destination (T1071)."""
    import ipaddress
    by_destination = defaultdict(list)
    dns = defaultdict(list)
    for event in events:
        details, ts, event_id = _event_fields(event)
        if not ts or not event_id:
            continue
        kind = str(getattr(event, "event_type", "") or (event.get("event_type", "") if isinstance(event, dict) else "")).lower()
        extra = details.get("extra") if isinstance(details.get("extra"), dict) else {}
        query = details.get("query_name") or details.get("query") or details.get("domain") or extra.get("query_name")
        answers = details.get("answer") or details.get("resolved_ip") or extra.get("query_results") or details.get("destination_ip") or details.get("dst_ip")
        if query and answers:
            if not isinstance(answers, (list, tuple, set)):
                answers = [answers]
            for answer in answers:
                dns[str(answer)].append((ts, str(query), event_id))
        dst = details.get("destination_ip") or details.get("dst_ip") or details.get("dest_ip")
        if not dst:
            continue
        try:
            addr = ipaddress.ip_address(str(dst))
        except ValueError:
            continue
        if is_internal_ip(str(dst)):
            continue
        source_ip = details.get("source_ip") or details.get("src_ip")
        if source_ip:
            try:
                source_address = ipaddress.ip_address(str(source_ip))
                if not is_internal_ip(str(source_address)):
                    continue
            except ValueError:
                pass
        is_connection = any(word in kind for word in ("network", "connection", "flow", "netflow", "tcp", "http")) or details.get("destination_port") or details.get("dst_port")
        if is_connection:
            by_destination[str(dst)].append((ts, event_id))
    findings = []
    for dst, rows in by_destination.items():
        rows.sort()
        if len(rows) < minimum_connections:
            continue
        # Collapse packet/retransmit records belonging to one connection burst.
        unique_times = {}
        for time in sorted({row[0] for row in rows}):
            previous = next(reversed(unique_times), None) if unique_times else None
            event_ids_at_time = [row[1] for row in rows if row[0] == time]
            if previous is not None and (time - previous).total_seconds() <= 10:
                unique_times[previous].extend(event_ids_at_time)
            else:
                unique_times[time] = event_ids_at_time
        times = sorted(unique_times)
        beacon_window = None
        median = 0
        for start in range(max(0, len(times) - minimum_connections + 1)):
            window_times = times[start:start + minimum_connections]
            intervals = [(window_times[i] - window_times[i - 1]).total_seconds() for i in range(1, len(window_times))]
            if not intervals or any(value <= 0 for value in intervals):
                continue
            candidate_median = sorted(intervals)[len(intervals) // 2]
            if candidate_median > 0 and max(abs(value - candidate_median) for value in intervals) <= max(tolerance_seconds, candidate_median * .15):
                beacon_window = window_times
                median = candidate_median
                break
        if not beacon_window:
            continue
        ids = [event_id for time in beacon_window for event_id in unique_times[time]]
        domains = sorted({domain for t, domain, _ in dns.get(dst, []) if t <= beacon_window[-1]})
        dns_ids = [event_id for t, _, event_id in dns.get(dst, []) if t <= beacon_window[-1]]
        findings.append({"rule_id": "periodic_c2_beaconing", "rule_name": "Periodic External Beaconing", "severity": "high", "mitre_technique": "T1071", "mitre_tactic": "Command and Control", "description": f"Periodic connections to external address {dst} were observed at an approximately {median:g}-second interval.", "dst_ip": dst, "matching_event_ids": sorted(set(ids + dns_ids)), "rule_information": {"tactic": "Command and Control", "destination_ip": dst, "domains": domains, "interval_seconds": median}})
    return findings


def detect_repeated_failed_logins(
    events,
    threshold: int | None = None,
    window_minutes: int | None = None,
) -> list[dict]:
    """
    Detect repeated failed logins from the same source IP.
    Threshold and time window default to the YAML rule settings.
    """
    rule = load_rule("ssh_bruteforce")
    config = rule["detection"]

    threshold = (
        threshold if threshold is not None
        else int(config["threshold"])
    )
    window_minutes = (
        window_minutes if window_minutes is not None
        else int(config["window_minutes"])
    )

    if threshold < 1 or window_minutes < 1:
        raise ValueError(
            "Detection threshold and window must be positive."
        )

    failures_by_ip = defaultdict(list)

    for event in events:
        details = event.details or {}

        searchable_text = " ".join(
            str(value)
            for value in [
                event.event_type,
                details.get("action", ""),
                details.get("result", ""),
                details.get("status", ""),
                details.get("message", ""),
                details.get("description", ""),
                details.get("event_id", ""),
            ]
        ).lower()

        is_failed_login = (
            any(word in searchable_text for word in [
                "fail",
                "failed",
                "failure",
                "invalid password",
                "authentication failure",
            ])
            and (
                "ssh" in searchable_text
                or str(details.get("protocol") or details.get("service") or "").lower() == "ssh"
                or str(details.get("destination_port") or details.get("dst_port") or "") == "22"
                or str(details.get("source_port") or details.get("src_port") or "") == "22"
            )
        )

        if not is_failed_login:
            continue

        source_ip = (
            details.get("source_ip")
            or details.get("src_ip")
            or details.get("src")
            or details.get("ip")
        )

        if source_ip and event.timestamp:
            failures_by_ip[str(source_ip)].append(event)

    findings = []
    window = timedelta(minutes=window_minutes)

    for source_ip, ip_events in failures_by_ip.items():
        ip_events.sort(key=lambda event: event.timestamp)
        active_events = deque()

        for event in ip_events:
            while (
                active_events
                and event.timestamp - active_events[0].timestamp > window
            ):
                active_events.popleft()

            active_events.append(event)

            if len(active_events) >= threshold:
                matching_events = list(active_events)

                findings.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["id"],
                    "display_name": rule["name"],
                    "severity": rule["severity"],
                    "mitre_technique": rule.get("mitre_technique"),
                    "rule_information": {
                        "threshold": threshold,
                        "window_minutes": window_minutes,
                        "grouped_by": config.get("group_by", "source_ip"),
                    },
                    "description": (
                        f"Potential brute-force activity: source IP "
                        f"{source_ip} had {len(matching_events)} "
                        f"failed login events within "
                        f"{window_minutes} minutes."
                    ),
                    "matching_event_ids": [
                        str(item.id) for item in matching_events
                    ],
                })

                # One finding per source IP for this run.
                break

    return findings




def detect_failed_then_successful_login(
    events,
    threshold: int | None = None,
    window_minutes: int | None = None,
) -> list[dict]:
    """
    Detect repeated failed logins followed by a successful login
    from the same source IP within the configured time window.
    """
    rule = load_rule("failed_then_successful_login")
    config = rule["detection"]

    threshold = (
        threshold if threshold is not None
        else int(config["threshold"])
    )
    window_minutes = (
        window_minutes if window_minutes is not None
        else int(config["window_minutes"])
    )

    if threshold < 1 or window_minutes < 1:
        raise ValueError(
            "Detection threshold and window must be positive."
        )

    failures_by_ip = defaultdict(list)
    successes_by_ip = defaultdict(list)

    window = timedelta(minutes=window_minutes)

    for event in events:
        details = event.details or {}

        source_ip = (
            details.get("source_ip")
            or details.get("src_ip")
            or details.get("src")
            or details.get("ip")
        )

        if not source_ip or event.timestamp is None:
            continue

        event_type = str(event.event_type or "").lower()
        status = str(
            details.get("status")
            or details.get("result")
            or ""
        ).lower()

        action = str(details.get("action") or "").lower()
        message = str(
            details.get("message")
            or details.get("description")
            or ""
        ).lower()

        searchable_text = " ".join([
            event_type,
            action,
            status,
            message,
            str(details.get("event_id") or "").lower(),
        ])

        is_login = any(word in searchable_text for word in [
            "login",
            "logon",
            "authentication",
            "ssh",
            "4624",
            "4625",
        ])

        if not is_login:
            continue

        is_failed = (
            status in {"failed", "failure", "unsuccessful"}
            or any(phrase in searchable_text for phrase in [
                "failed password",
                "login failed",
                "failed login",
                "authentication failure",
                "invalid password",
            ])
            or event_type in {
                "ssh_failed",
                "login_failed",
                "failed_login",
            }
        )

        is_successful = (
            status in {"success", "successful", "succeeded", "accepted"}
            or any(phrase in searchable_text for phrase in [
                "accepted password",
                "accepted publickey",
                "login successful",
                "successful login",
                "logged on successfully",
            ])
            or event_type in {
                "ssh_success",
                "login_success",
                "successful_login",
            }
        )

        if is_failed:
            failures_by_ip[str(source_ip)].append(event)
        elif is_successful:
            successes_by_ip[str(source_ip)].append(event)

    findings = []

    for source_ip, successful_events in successes_by_ip.items():
        failures = sorted(
            failures_by_ip.get(source_ip, []),
            key=lambda item: item.timestamp,
        )

        successful_events.sort(key=lambda item: item.timestamp)

        for success_event in successful_events:
            matching_failures = [
                failure
                for failure in failures
                if timedelta(0)
                < success_event.timestamp - failure.timestamp
                <= window
            ]

            if len(matching_failures) < threshold:
                continue

            # Keep only the failures within the window.
            matching_events = matching_failures + [success_event]

            findings.append({
                "rule_id": rule["id"],
                "rule_name": rule["id"],
                "display_name": rule["name"],
                "severity": rule["severity"],
                "mitre_technique": rule.get("mitre_technique"),
                "description": (
                    f"Potential brute-force activity: source IP "
                    f"{source_ip} had {len(matching_failures)} "
                    f"failed login events within {window_minutes} "
                    f"minutes, followed by a successful login."
                ),
                "rule_information": {
                    "threshold": threshold,
                    "window_minutes": window_minutes,
                    "grouped_by": config.get(
                        "group_by", "source_ip"
                    ),
                    "sequence": [
                        "repeated_failed_logins",
                        "successful_login",
                    ],
                },
                "matching_event_ids": [
                    str(item.id) for item in matching_events
                ],
            })

            # One finding per source IP for this run.
            break

    return findings



def detect_privilege_escalation(events) -> list[dict]:
    """
    Detect explicit privilege escalation indicators and selected
    suspicious privilege-use activity.
    """
    rule = load_rule("privilege_escalation")
    config = rule["detection"]

    normalize = lambda value: (
        str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    )

    configured_types = {
        normalize(item)
        for item in config["event_types"]
    }

    events_by_user = defaultdict(list)

    explicit_indicators = (
        "privilege escalation",
        "privilege elevation",
        "uac bypass",
        "setuid",
        "token impersonation",
    )

    suspicious_actions = {
        "uac_bypass",
        "setuid",
        "token_impersonation",
        "sudoers_change",
        "unauthorized_privilege_change",
    }

    for event in events:
        details = event.details or {}

        event_type = normalize(event.event_type)
        action = normalize(details.get("action"))
        message = normalize(
            details.get("message") or details.get("description")
        )
        status = normalize(
            details.get("status") or details.get("result")
        )

        searchable_text = f"{event_type} {action} {message}"

        is_explicit = (
            event_type in configured_types
            and event_type != "privilege_use"
        ) or any(
            indicator in searchable_text
            for indicator in explicit_indicators
        )

        is_suspicious_action = (
            action in suspicious_actions
            or event_type in suspicious_actions
        )

        # A routine privilege-use event alone is not sufficient.
        if not is_explicit and not is_suspicious_action:
            continue

        # Ignore events explicitly reported as failed when the
        # detection concerns a successful privilege change.
        if status in {
            "failed", "failure", "unsuccessful", "denied", "rejected"
        }:
            continue

        username = (
            details.get("username")
            or details.get("user")
            or details.get("account")
            or "unknown"
        )
        username = str(username).strip() or "unknown"

        events_by_user[username].append(event)

    findings = []

    for username, matching_events in events_by_user.items():
        findings.append({
            "rule_id": rule["id"],
            "rule_name": rule["id"],
            "display_name": rule["name"],
            "severity": rule["severity"],
            "mitre_technique": rule.get("mitre_technique"),
            "description": (
                f"Potential privilege escalation activity involving "
                f"user '{username}', supported by "
                f"{len(matching_events)} event(s)."
            ),
            "rule_information": {
                "event_types": sorted(configured_types),
                "grouped_by": config.get("group_by", "username"),
            },
            "matching_event_ids": [
                str(item.id) for item in matching_events
            ],
        })

    return findings



def detect_lateral_movement(events) -> list[dict]:
    """
    Detect successful remote authentication between distinct hosts.
    Both source and destination hosts must be available.
    """
    rule = load_rule("lateral_movement")
    config = rule["detection"]

    normalize = lambda value: (
        str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    )

    configured_types = {
        normalize(event_type)
        for event_type in config["event_types"]
    }

    successful_statuses = {
        "success",
        "successful",
        "succeeded",
        "accepted",
    }

    remote_event_types = {
        "ssh_success",
        "remote_login",
    }

    events_by_user_and_hosts = defaultdict(list)

    for event in events:
        details = event.details or {}

        event_type = normalize(event.event_type)

        if event_type not in configured_types:
            continue

        status = normalize(
            details.get("status") or details.get("result")
        )

        # Explicit success event types can establish success.
        # Generic login events require a successful status.
        is_successful = (
            event_type in remote_event_types
            or event_type in {
                "login_success",
                "successful_login",
            }
        ) or status in successful_statuses

        if not is_successful:
            continue

        source_host = (
            details.get("source_host")
            or details.get("src_host")
            or details.get("source_ip")
            or details.get("src_ip")
            or details.get("src")
        )

        destination_host = (
            details.get("destination_host")
            or details.get("dest_host")
            or details.get("destination_ip")
            or details.get("dest_ip")
            or details.get("dst_ip")
            or details.get("dst")
            or details.get("dest")
        )

        # Do not infer missing hosts or report incomplete host pairs.
        if not source_host or not destination_host:
            continue

        source_host = str(source_host).strip().lower()
        destination_host = str(destination_host).strip().lower()

        if not source_host or not destination_host:
            continue

        if source_host == destination_host:
            continue

        username = (
            details.get("username")
            or details.get("user")
            or details.get("account")
            or "unknown"
        )
        username = str(username).strip() or "unknown"

        key = (username, source_host, destination_host)
        events_by_user_and_hosts[key].append(event)

    findings = []

    for (username, source_host, destination_host), matching_events in (
        events_by_user_and_hosts.items()
    ):
        findings.append({
            "rule_id": rule["id"],
            "rule_name": rule["id"],
            "display_name": rule["name"],
            "severity": rule["severity"],
            "mitre_technique": rule.get("mitre_technique"),
            "description": (
                f"Potential lateral movement: user '{username}' "
                f"recorded a successful login from "
                f"'{source_host}' to '{destination_host}'. "
                f"Supporting events: {len(matching_events)}."
            ),
            "rule_information": {
                "event_types": sorted(configured_types),
                "grouped_by": config.get("group_by", "username"),
                "username": username,
                "source_host": source_host,
                "destination_host": destination_host,
            },
            "matching_event_ids": [
                str(item.id) for item in matching_events
            ],
        })

    return findings



_SQLI_REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("quote_tampering", re.compile(r"(?:[?&]\w+=-?\d+|where\s+\w+\s*=\s*-?\d+)['\"](?:\s|$|--|#|;)", re.IGNORECASE)),
    ("boolean_tautology", re.compile(r"(?:'\s*or\s*'1'\s*=\s*'1|(?:\bor\b|\band\b)\s+['\"]?1['\"]?\s*=\s*['\"]?[12]\b)", re.IGNORECASE)),
    ("order_by_enum", re.compile(r"\border\s+by\s+\d+\s*(?:--|#|/\*)", re.IGNORECASE)),
    ("union_select", re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE)),
    ("information_schema", re.compile(r"\binformation_schema\b", re.IGNORECASE)),
    ("db_fingerprint_func", re.compile(r"\b(?:version|database|current_user)\s*\(\s*\)|\bgroup_concat\s*\(", re.IGNORECASE)),
    ("time_or_oob_sqli", re.compile(r"\b(?:sleep|benchmark|extractvalue|updatexml|load_file)\s*\(|\b(?:waitfor\s+delay|xp_cmdshell|into\s+outfile)\b|;\s*drop\s+table\b", re.IGNORECASE)),
    ("sqlmap_ua", re.compile(r"\bsqlmap(?:/|\b)", re.IGNORECASE)),
]


def _decode_web_text(value: str) -> str:
    """URL-decode query strings (converting + and %20 to spaces) safely."""
    text = str(value or "")
    if not text:
        return ""
    decoded = unquote_plus(text)
    if "%" in decoded:
        decoded = unquote_plus(decoded)
    return decoded


def extract_sqli_indicators(event) -> list[str]:
    """Return matched SQL injection indicator names for web, WAF, or DB query events."""
    is_dict = isinstance(event, dict)
    details = (event.get("details") if is_dict else getattr(event, "details", None)) or {}
    if not isinstance(details, dict):
        details = {}
    extra = details.get("extra") if isinstance(details.get("extra"), dict) else {}

    raw_event_type = event.get("event_type") if is_dict else getattr(event, "event_type", "")
    ev_type = str(raw_event_type or "").strip().lower().replace("-", "_").replace(" ", "_")

    # Restrict matching to web, WAF, and database query events so non-SQL host logs do not trigger.
    source_name = str((event.get("source") if is_dict else getattr(event, "source", "")) or extra.get("source") or "").strip().lower()
    source_file = str(details.get("source_file") or "").strip().lower()
    is_waf_alert = ev_type in {"waf_alert", "edr_alert", "json_event"} and (
        "waf" in source_name or "waf" in source_file or bool(extra.get("uri")) or bool(details.get("uri"))
    )
    if ev_type not in {"http_request", "web_request", "web_access", "http", "db_query", "waf_alert"} and not is_waf_alert:
        return []

    raw_candidates = [
        details.get("url", ""),
        details.get("path", ""),
        details.get("query_string", ""),
        details.get("query", ""),
        details.get("request_uri", ""),
        details.get("request", ""),
        details.get("uri", ""),
        details.get("sql", ""),
        details.get("command_line", ""),
        details.get("user_agent", ""),
        details.get("body", ""),
        extra.get("uri", ""),
    ]
    if is_waf_alert or ev_type == "db_query":
        raw_candidates.extend([
            details.get("message", ""),
            details.get("action", ""),
            extra.get("message", ""),
        ])
    if ev_type in {"http_request", "web_request", "web_access", "http"}:
        raw_candidates.extend([
            details.get("raw", ""),
            details.get("raw_message", ""),
        ])

    decoded_candidates = [
        _decode_web_text(str(val))
        for val in raw_candidates
        if val
    ]
    if not decoded_candidates:
        return []

    searchable = "\n".join(decoded_candidates)
    return [name for name, pattern in _SQLI_REGEX_PATTERNS if pattern.search(searchable)]


def detect_web_sql_injection(events) -> list[dict]:
    """
    Detect potential SQL injection indicators in web, WAF, and DB query events.
    These indicators require investigation and do not prove exploitation.
    """
    rule = load_rule("web_sql_injection")
    config = rule["detection"]

    normalize = lambda value: (
        str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    )

    configured_types = {
        normalize(item) for item in config["event_types"]
    }

    events_by_source = defaultdict(list)

    for event in events:
        details, ts, event_id = _event_fields(event)
        if not event_id:
            continue
        event_type = normalize(event.get("event_type") if isinstance(event, dict) else getattr(event, "event_type", ""))

        if event_type not in configured_types:
            continue

        matched_patterns = extract_sqli_indicators(event)
        if not matched_patterns:
            continue

        source_ip = (
            details.get("source_ip")
            or details.get("src_ip")
            or details.get("client_ip")
            or details.get("ip")
            or "unknown"
        )
        events_by_source[str(source_ip)].append((event, matched_patterns, ts))

    # Determine unambiguous non-IP server host in the event batch as fallback
    non_ip_case_hosts = {
        str(d.get("host")).strip()
        for d in ((getattr(e, "details", None) or (e.get("details", {}) if isinstance(e, dict) else {}) or {}) for e in events)
        if d.get("host")
        and str(d.get("host")).strip().casefold() not in {"unknown", "unknown_host", "-"}
        and not _is_ip_address(d.get("host"))
        and not str(d.get("host")).strip().isdigit()
    }
    inferred_server_host = next(iter(non_ip_case_hosts)) if len(non_ip_case_hosts) == 1 else None

    # Associate DB-level SQLi queries (which lack a client src_ip) with the web SQLi source
    # when there is a single attributed source IP on the same case/host.
    attributed_ips = [ip for ip in events_by_source if ip != "unknown"]
    if "unknown" in events_by_source and len(attributed_ips) == 1:
        unknown_matches = events_by_source.pop("unknown")
        events_by_source[attributed_ips[0]].extend(unknown_matches)

    findings = []

    for source_ip, matches in events_by_source.items():
        matched_events = [item[0] for item in matches]
        patterns = sorted({
            pattern
            for _, matched, _ in matches
            for pattern in matched
        })
        victim_hosts = sorted({
            str(d.get("host")).strip()
            for d in ((getattr(item, "details", None) or (item.get("details", {}) if isinstance(item, dict) else {}) or {}) for item in matched_events)
            if d.get("host")
            and str(d.get("host")).strip().casefold() not in {"unknown", "unknown_host", "-"}
            and str(d.get("host")).strip() != source_ip
            and not _is_ip_address(d.get("host"))
        })
        if not victim_hosts and inferred_server_host:
            victim_hosts = [inferred_server_host]
        source_ips = [source_ip] if source_ip and source_ip != "unknown" else []
        target_host = victim_hosts[0] if victim_hosts else None
        matched_timestamps = sorted(ts for _, _, ts in matches if ts is not None)
        first_seen = matched_timestamps[0].isoformat() if matched_timestamps else None
        last_seen = matched_timestamps[-1].isoformat() if matched_timestamps else None

        findings.append({
            "rule_id": rule["id"],
            "rule_name": rule["id"],
            "display_name": rule["name"],
            "severity": rule["severity"],
            "mitre_technique": rule.get("mitre_technique") or "T1190",
            "mitre_tactic": rule.get("mitre_tactic") or "Initial Access",
            "actor": source_ips[0] if source_ips else None,
            "target_host": target_host,
            "host": target_host or "unknown",
            "src_ip": source_ips[0] if source_ips else None,
            "source_ips": source_ips,
            "hosts": victim_hosts,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "description": (
                f"Potential SQL injection indicators detected in "
                f"{len(matched_events)} web/database event(s) associated with "
                f"source IP '{source_ip}'."
            ),
            "rule_information": {
                "event_types": sorted(configured_types),
                "grouped_by": config.get("group_by", "source_ip"),
                "matched_patterns": patterns,
                "hosts": victim_hosts,
                "target_host": target_host,
                "source_ips": source_ips,
                "src_ips": source_ips,
                "tactic": rule.get("mitre_tactic") or "Initial Access",
            },
            "matching_event_ids": [
                str(getattr(item, "id", None) or (item.get("id") if isinstance(item, dict) else ""))
                for item in matched_events
            ],
        })

    return findings



def detect_data_exfiltration(events) -> list[dict]:
    """Detect large or cumulative suspicious outbound transfers."""
    rule = load_rule("data_exfiltration")
    config = rule["detection"]

    threshold_bytes = int(
        config.get("transfer_threshold_bytes", 104857600)
    )
    window_minutes = int(
        config.get("cumulative_window_minutes", 60)
    )

    if threshold_bytes < 1 or window_minutes < 1:
        raise ValueError(
            "Transfer threshold and cumulative window must be positive."
        )

    normalize = lambda value: (
        str(value or "").strip().lower()
        .replace("-", "_").replace(" ", "_")
    )

    configured_types = {
        normalize(item) for item in config["event_types"]
    }

    explicit_indicators = {
        "data_exfiltration",
        "exfiltration_detected",
        "possible_exfiltration",
    }

    outbound_values = {
        "outbound", "egress", "upload", "send",
        "sent", "outgoing",
    }

    records_by_source = defaultdict(list)

    for event in events:
        details = event.details or {}
        event_type = normalize(event.event_type)

        if event_type not in configured_types:
            continue

        direction = normalize(
            details.get("direction")
            or details.get("transfer_direction")
            or details.get("traffic_direction")
        )

        action = normalize(details.get("action"))
        status = normalize(
            details.get("status") or details.get("result")
        )

        message = str(
            details.get("message")
            or details.get("description")
            or ""
        ).lower()

        # Do not count transfers that explicitly failed.
        if status in {
            "failed", "failure", "denied",
            "rejected", "unsuccessful",
        }:
            continue

        explicit = (
            event_type in explicit_indicators
            or action in explicit_indicators
            or any(
                phrase in message
                for phrase in (
                    "data exfiltration detected",
                    "possible data exfiltration",
                    "suspected data exfiltration",
                )
            )
        )

        raw_size = details.get("bytes_transferred")
        if raw_size is None:
            raw_size = details.get("bytes_sent")
        if raw_size is None:
            raw_size = details.get("size_bytes")
        if raw_size is None:
            raw_size = details.get("bytes_out")

        try:
            size_bytes = int(raw_size) if raw_size is not None else 0
        except (TypeError, ValueError):
            size_bytes = 0

        if size_bytes < 0:
            continue

        # bytes_out itself indicates outbound traffic in this data format.
        outbound_evidence = (
            direction in outbound_values
            or action in outbound_values
            or details.get("bytes_out") is not None
            or event_type in {"outbound_transfer", "file_upload"}
        )

        if not explicit and not (outbound_evidence and size_bytes > 0):
            continue

        source_ip = str(
            details.get("source_ip")
            or details.get("src_ip")
            or details.get("src")
            or "unknown"
        )

        destination = str(
            details.get("destination_ip")
            or details.get("dest_ip")
            or details.get("dst_ip")
            or details.get("destination_host")
            or details.get("dest_host")
            or "unknown"
        )

        records_by_source[source_ip].append({
            "event": event,
            "destination": destination,
            "size_bytes": size_bytes,
            "outbound": outbound_evidence,
            "explicit": explicit,
        })

    findings = []
    window = timedelta(minutes=window_minutes)

    for source_ip, records in records_by_source.items():
        # Explicit indicators can independently produce a finding.
        matched_by_id = {
            str(record["event"].id): record
            for record in records
            if record["explicit"]
        }

        # Only timestamped outbound transfers contribute to rolling totals.
        transfers = sorted(
            [
                record for record in records
                if record["outbound"]
                and record["size_bytes"] > 0
                and record["event"].timestamp is not None
            ],
            key=lambda record: record["event"].timestamp,
        )

        left = 0
        window_total = 0

        for right, current in enumerate(transfers):
            current_time = current["event"].timestamp
            window_total += current["size_bytes"]

            # Remove transfers older than the rolling time window.
            while (
                left <= right
                and current_time - transfers[left]["event"].timestamp
                > window
            ):
                window_total -= transfers[left]["size_bytes"]
                left += 1

            if window_total >= threshold_bytes:
                # Keep the events that contributed to this threshold crossing.
                for record in transfers[left:right + 1]:
                    matched_by_id[str(record["event"].id)] = record

        if not matched_by_id:
            continue

        matched_records = list(matched_by_id.values())
        matched_events = [record["event"] for record in matched_records]

        total_bytes = sum(
            record["size_bytes"] for record in matched_records
        )

        destinations = sorted({
            record["destination"] for record in matched_records
        })

        explicit_count = sum(
            record["explicit"] for record in matched_records
        )

        findings.append({
            "rule_id": rule["id"],
            "rule_name": rule["id"],
            "display_name": rule["name"],
            "severity": rule["severity"],
            "mitre_technique": rule.get("mitre_technique"),
            "description": (
                f"Potential data exfiltration involving source "
                f"'{source_ip}': {len(matched_events)} matching "
                f"event(s), with {total_bytes} recorded bytes "
                f"and {explicit_count} explicit exfiltration "
                f"indicator(s)."
            ),
            "rule_information": {
                "event_types": sorted(configured_types),
                "grouped_by": config.get("group_by", "source_ip"),
                "transfer_threshold_bytes": threshold_bytes,
                "cumulative_window_minutes": window_minutes,
                "total_bytes_recorded": total_bytes,
                "destinations": destinations,
                "explicit_indicator_count": explicit_count,
            },
            "matching_event_ids": [
                str(event.id) for event in matched_events
            ],
        })

    return findings




def detect_dns_tunneling(events) -> list[dict]:
    """
    Detect potentially suspicious DNS tunneling indicators.

    Uses query length, unusually long labels, and repeated unique
    queries. These heuristics identify candidates for investigation,
    not confirmed DNS tunneling.
    """
    rule = load_rule("dns_tunneling")
    config = rule["detection"]

    query_length_threshold = int(
        config.get("query_length_threshold", 100)
    )
    subdomain_length_threshold = int(
        config.get("subdomain_length_threshold", 50)
    )
    unique_query_threshold = int(
        config.get("unique_query_threshold", 20)
    )

    if min(
        query_length_threshold,
        subdomain_length_threshold,
        unique_query_threshold,
    ) < 1:
        raise ValueError("DNS detection thresholds must be positive.")

    normalize = lambda value: (
        str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    )

    configured_types = {
        normalize(item) for item in config["event_types"]
    }

    events_by_source = defaultdict(list)

    explicit_indicators = (
        "dns tunneling detected",
        "possible dns tunnel",
        "suspected dns exfiltration",
    )

    for event in events:
        details = event.details or {}
        event_type = normalize(event.event_type)

        if event_type not in configured_types:
            continue

        query = str(
            details.get("query_name")
            or details.get("query")
            or details.get("domain")
            or details.get("hostname")
            or ""
        ).strip().rstrip(".").lower()

        message = str(
            details.get("message")
            or details.get("description")
            or ""
        ).lower()

        explicit_match = any(
            indicator in message
            for indicator in explicit_indicators
        )

        if not query and not explicit_match:
            continue

        labels = query.split(".") if query else []
        longest_label = max(
            (len(label) for label in labels),
            default=0,
        )

        # The leftmost labels commonly contain encoded tunnel data.
        suspicious_length = (
            len(query) >= query_length_threshold
            or longest_label >= subdomain_length_threshold
        )

        # Look for long, encoded-looking labels. This is only a
        # heuristic; legitimate services also use encoded subdomains.
        encoded_looking = any(
            len(label) >= subdomain_length_threshold
            and sum(char.isalnum() or char in "-_" for char in label)
                / max(len(label), 1) > 0.9
            for label in labels[:-2] if len(labels) > 2
        )

        if not (
            explicit_match
            or (suspicious_length and encoded_looking)
        ):
            continue

        source_ip = str(
            details.get("source_ip")
            or details.get("src_ip")
            or details.get("client_ip")
            or details.get("src")
            or "unknown"
        )

        events_by_source[source_ip].append({
            "event": event,
            "query": query,
            "query_length": len(query),
            "longest_label_length": longest_label,
            "explicit": explicit_match,
        })

    findings = []

    for source_ip, records in events_by_source.items():
        matched_events = [record["event"] for record in records]

        unique_queries = {
            record["query"]
            for record in records
            if record["query"]
        }

        long_query_records = [
            record for record in records
            if record["query_length"] >= query_length_threshold
        ]

        long_label_records = [
            record for record in records
            if record["longest_label_length"]
            >= subdomain_length_threshold
        ]

        explicit_count = sum(
            record["explicit"] for record in records
        )

        # Avoid treating a single long DNS query as proof of tunneling.
        # An explicit security alert can independently justify a finding.
        if (
            len(unique_queries) < unique_query_threshold
            and explicit_count == 0
        ):
            continue

        findings.append({
            "rule_id": rule["id"],
            "rule_name": rule["id"],
            "display_name": rule["name"],
            "severity": rule["severity"],
            "mitre_technique": rule.get("mitre_technique"),
            "description": (
                f"Potential DNS tunneling indicators associated with "
                f"source '{source_ip}': {len(unique_queries)} unique "
                f"query name(s), {len(long_query_records)} long "
                f"query event(s), and {len(long_label_records)} "
                f"event(s) with long labels."
            ),
            "rule_information": {
                "event_types": sorted(configured_types),
                "grouped_by": config.get("group_by", "source_ip"),
                "unique_query_count": len(unique_queries),
                "query_length_threshold": query_length_threshold,
                "subdomain_length_threshold": subdomain_length_threshold,
                "explicit_indicator_count": explicit_count,
            },
            "matching_event_ids": [
                str(item.id) for item in matched_events
            ],
        })

    return findings


def detect_web_scanner_recon(events) -> list[dict]:
    """
    Detect web vulnerability scanner activity (T1595) via known scanner user
    agents OR 10+ HTTP 404 responses from one IP within 60 seconds.
    """
    rule = load_rule("web_scanner_recon")
    config = rule["detection"]

    normalize = lambda value: (
        str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    )
    configured_types = {normalize(item) for item in config.get("event_types", [])}
    scanner_agents = [str(ua).strip().lower() for ua in config.get("scanner_user_agents", []) if ua]
    target_status = int(config.get("status_code", 404))
    threshold = int(config.get("threshold", 10))
    window = timedelta(seconds=int(config.get("window_seconds", 60)))

    if threshold <= 0 or window.total_seconds() <= 0:
        raise ValueError("Scanner detection threshold and window must be positive.")

    events_by_ip = defaultdict(list)
    for event in events:
        details, ts, event_id = _event_fields(event)
        if not event_id:
            continue
        raw_type = event.get("event_type") if isinstance(event, dict) else getattr(event, "event_type", "")
        if normalize(raw_type) not in configured_types:
            continue
        source_ip = (
            details.get("source_ip")
            or details.get("src_ip")
            or details.get("client_ip")
            or details.get("ip")
        )
        if not source_ip:
            continue
        events_by_ip[str(source_ip)].append((event, details, ts, event_id))

    non_ip_case_hosts = {
        str(d.get("host")).strip()
        for d in ((getattr(e, "details", None) or (e.get("details", {}) if isinstance(e, dict) else {}) or {}) for e in events)
        if d.get("host")
        and str(d.get("host")).strip().casefold() not in {"unknown", "unknown_host", "-"}
        and not _is_ip_address(d.get("host"))
        and not str(d.get("host")).strip().isdigit()
    }
    inferred_server_host = next(iter(non_ip_case_hosts)) if len(non_ip_case_hosts) == 1 else None

    findings = []
    for source_ip, ip_records in events_by_ip.items():
        ip_records.sort(key=lambda item: item[2].timestamp() if item[2] else 0.0)

        ua_matched_ids: set[str] = set()
        not_found_window = deque()
        burst_matched_ids: set[str] = set()

        for _, details, ts, event_id in ip_records:
            ua_text = " ".join(
                str(details.get(k) or "")
                for k in ("user_agent", "UserAgent")
            ).lower()
            if ua_text and any(agent in ua_text for agent in scanner_agents):
                ua_matched_ids.add(event_id)

            status_raw = details.get("status_code") or details.get("status")
            try:
                status_int = int(status_raw) if status_raw is not None else None
            except (TypeError, ValueError):
                status_int = None

            if status_int == target_status and ts is not None:
                while not_found_window and ts - not_found_window[0][0] > window:
                    not_found_window.popleft()
                not_found_window.append((ts, event_id))
                if len(not_found_window) >= threshold:
                    burst_matched_ids.update(eid for _, eid in not_found_window)

        all_matched_ids = ua_matched_ids | burst_matched_ids
        if not all_matched_ids:
            continue

        matched_records = [rec for rec in ip_records if rec[3] in all_matched_ids]
        victim_hosts = sorted({
            str(d.get("host")).strip()
            for _, d, _, _ in matched_records
            if d.get("host")
            and str(d.get("host")).strip().casefold() not in {"unknown", "unknown_host", "-"}
            and str(d.get("host")).strip() != source_ip
            and not _is_ip_address(d.get("host"))
        })
        if not victim_hosts and inferred_server_host:
            victim_hosts = [inferred_server_host]

        matched_timestamps = sorted(ts for _, _, ts, _ in matched_records if ts is not None)
        first_seen = matched_timestamps[0].isoformat() if matched_timestamps else None
        last_seen = matched_timestamps[-1].isoformat() if matched_timestamps else None
        target_host = victim_hosts[0] if victim_hosts else None

        findings.append({
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "display_name": rule["name"],
            "severity": rule["severity"],
            "mitre_technique": rule.get("mitre_technique") or "T1595",
            "mitre_tactic": rule.get("mitre_tactic") or "Reconnaissance",
            "actor": source_ip,
            "target_host": target_host,
            "host": target_host or "unknown",
            "hosts": victim_hosts,
            "src_ip": source_ip,
            "source_ips": [source_ip],
            "first_seen": first_seen,
            "last_seen": last_seen,
            "description": (
                f"Automated web scanner reconnaissance detected from source IP "
                f"'{source_ip}' across {len(matched_records)} HTTP request(s)."
            ),
            "rule_information": {
                "event_types": sorted(configured_types),
                "grouped_by": config.get("group_by", "source_ip"),
                "hosts": victim_hosts,
                "target_host": target_host,
                "source_ips": [source_ip],
                "src_ips": [source_ip],
                "tactic": rule.get("mitre_tactic") or "Reconnaissance",
                "scanner_ua_matches": len(ua_matched_ids),
                "not_found_burst_matches": len(burst_matched_ids),
            },
            "matching_event_ids": [rec[3] for rec in matched_records],
        })

    return findings
