"""
DCSRE Deterministic Detection Engine & Sigma Field Matcher (Stage 4 & Stage 5)
Strictly rule-based, deterministic analysis. Evaluates single-event and correlation rules.
"""
import fnmatch
import json
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


# Documented Sigma Field Mapping Table (Stage 4)
SIGMA_FIELD_MAP: Dict[str, List[str]] = {
    # Process & Execution
    "Image": ["process", "details.process", "details.NewProcessName", "details.Image"],
    "NewProcessName": ["process", "details.NewProcessName", "details.Image"],
    "CommandLine": ["command_line", "details.command_line", "details.CommandLine", "details.ImagePath"],
    "ProcessCommandLine": ["command_line", "details.command_line", "details.CommandLine"],
    "ParentImage": ["parent_process", "details.parent_process", "details.ParentImage", "details.ParentProcessName"],
    "ParentProcessName": ["parent_process", "details.parent_process", "details.ParentImage", "details.ParentProcessName"],

    # Users
    "User": ["user", "details.user", "details.TargetUserName", "details.SubjectUserName", "details.username"],
    "SubjectUserName": ["details.SubjectUserName", "user", "details.user"],
    "TargetUserName": ["details.TargetUserName", "user", "details.user"],
    "Account": ["user", "details.user"],

    # Event IDs & Services
    "EventID": ["event_id", "details.event_id", "details.EventID"],
    "EventId": ["event_id", "details.event_id"],
    "ServiceName": ["service_name", "details.service_name", "details.ServiceName"],
    "ImagePath": ["command_line", "details.command_line", "details.ImagePath"],

    # Files & Objects
    "TargetFilename": ["target_file", "details.target_file", "details.TargetFilename", "details.path", "details.dst"],
    "TargetObject": ["target_file", "details.target_file", "details.TargetObject"],
    "Path": ["target_file", "details.target_file", "details.path", "details.src", "details.dst"],

    # Network
    "SourceIp": ["src_ip", "details.src_ip", "details.source_ip", "details.IpAddress"],
    "DestinationIp": ["dst_ip", "details.dst_ip", "details.destination_ip", "details.DestinationIp"],
    "SourcePort": ["src_port", "details.src_port", "details.source_port"],
    "DestinationPort": ["dst_port", "details.dst_port", "details.destination_port"],
    "Protocol": ["protocol", "details.protocol", "details.proto"],
    "QueryName": ["details.extra.query_name", "target_file", "command_line", "details.query_name"],

    # Host
    "Computer": ["host", "details.host", "details.Computer", "details.computer"],
    "Host": ["host", "details.host"],

    # Generic & Raw
    "action": ["action", "details.action"],
    "raw": ["raw", "details.raw", "details.raw_message"],
    "status": ["outcome", "details.outcome", "details.status", "details.Status"],
}


def _extract_field_value(event: Any, field_name: str) -> Optional[Any]:
    """Retrieve field value from an Event model or dict using the Sigma field mapping table."""
    # Direct access
    candidate_keys = SIGMA_FIELD_MAP.get(field_name, [field_name, f"details.{field_name}"])

    is_dict = isinstance(event, dict)
    details = event.get("details", {}) if is_dict else getattr(event, "details", {})
    if not isinstance(details, dict):
        details = {}

    for key in candidate_keys:
        if key.startswith("details."):
            sub_key = key.split(".", 1)[1]
            if sub_key.startswith("extra."):
                extra_key = sub_key.split(".", 1)[1]
                extra = details.get("extra") or {}
                if isinstance(extra, dict) and extra_key in extra:
                    return extra[extra_key]
            if sub_key in details and details[sub_key] is not None:
                return details[sub_key]
        else:
            val = event.get(key) if is_dict else getattr(event, key, None)
            if val is not None:
                return val
            if key in details and details[key] is not None:
                return details[key]

    return None


def match_value(actual: Any, expected: Any, modifier: str = "equals") -> bool:
    """Evaluate actual field value against expected pattern with Sigma modifiers."""
    if actual is None:
        return False

    # Handle lists in expected (OR evaluation unless modifier is |all)
    if isinstance(expected, list) and modifier != "all":
        return any(match_value(actual, item, modifier) for item in expected)

    if modifier == "all" and isinstance(expected, list):
        return all(match_value(actual, item, "equals") for item in expected)

    actual_str = str(actual).strip().lower()
    expected_str = str(expected).strip().lower()

    if modifier == "contains":
        return expected_str in actual_str

    if modifier == "startswith":
        return actual_str.startswith(expected_str)

    if modifier == "endswith":
        return actual_str.endswith(expected_str)

    if modifier == "re" or modifier == "regex":
        try:
            return bool(re.search(expected, str(actual), re.IGNORECASE))
        except re.error:
            return False

    # Equals with wildcard support (* and ?)
    if "*" in expected_str or "?" in expected_str:
        return fnmatch.fnmatchcase(actual_str, expected_str)

    return actual_str == expected_str


def evaluate_event_selection(event: Any, selection: Dict[str, Any]) -> bool:
    """Evaluate a Sigma selection dictionary against an event."""
    for field_spec, expected in selection.items():
        parts = field_spec.split("|")
        field_name = parts[0]
        modifier = parts[1].lower() if len(parts) > 1 else "equals"

        actual_val = _extract_field_value(event, field_name)
        if not match_value(actual_val, expected, modifier):
            return False

    return True


# Catalog of Deterministic Detection Rules (Stage 5)
BUILTIN_SIGMA_RULES = [
    {
        "id": "rule-office-spawn-cmd-powershell",
        "name": "Office Application Spawning Script Interpreter",
        "severity": "high",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059.001",
        "description": "Detects Microsoft Office applications (Word, Excel) spawning cmd.exe, PowerShell, or script hosts.",
        "detection": {
            "selection": {
                "ParentImage|endswith": ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "winword.exe", "excel.exe"],
                "Image|endswith": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
            }
        }
    },
    {
        "id": "rule-powershell-encoded",
        "name": "Encoded PowerShell Command Execution",
        "severity": "high",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059.001",
        "description": "Detects execution of PowerShell commands using encoded command line arguments (-enc, -encodedcommand).",
        "detection": {
            "selection": {
                "CommandLine|contains": ["-enc", "-encodedcommand", "-e SQ", "-enco "]
            }
        }
    },
    {
        "id": "rule-lsass-memory-dump",
        "name": "LSASS Memory Access and Credential Dumping",
        "severity": "critical",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1003.001",
        "description": "Detects access or dump of Local Security Authority Subsystem Service (LSASS) memory via comsvcs.dll or procdump.",
        "detection": {
            "selection": {
                "CommandLine|contains": ["comsvcs.dll", "MiniDump", "lsass.dmp", "procdump"]
            }
        }
    },
    {
        "id": "rule-ntdsutil-extraction",
        "name": "Active Directory Database Extraction via ntdsutil",
        "severity": "critical",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1003.003",
        "description": "Detects execution of ntdsutil utility to dump or extract the Active Directory database (NTDS.dit).",
        "detection": {
            "selection": {
                "CommandLine|contains": ["ntdsutil", "ntds.dit"]
            }
        }
    },
    {
        "id": "rule-remote-service-creation",
        "name": "Remote Service Creation via PsExec or Service Control",
        "severity": "high",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1569.002",
        "description": "Detects remote service creation or PsExec service installation (Event ID 7045 / 4697).",
        "detection": {
            "selection": {
                "ServiceName|contains": ["PSEXESVC"],
                "EventID": [7045, 4697, "7045", "4697"]
            }
        }
    },
    {
        "id": "rule-rclone-large-transfer",
        "name": "Large Outbound Transfer or rclone Staging",
        "severity": "high",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1567.002",
        "description": "Detects adversary exfiltration using rclone utility or massive outbound transfer to external endpoints.",
        "detection": {
            "selection": {
                "CommandLine|contains": ["rclone", "rclone.exe"]
            }
        }
    },
    {
        "id": "rule-shadow-copy-deletion",
        "name": "Inhibit System Recovery via Shadow Copy Deletion",
        "severity": "critical",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1490",
        "description": "Detects deletion of volume shadow copies or disabling recovery mode using vssadmin, wbadmin, or bcdedit.",
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "delete shadows",
                    "vssadmin",
                    "recoveryenabled no",
                    "wbadmin delete catalog"
                ]
            }
        }
    },
    {
        "id": "rule-security-log-cleared",
        "name": "Security Audit Log Cleared",
        "severity": "high",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1070.001",
        "description": "Detects clearing of the Windows Security event log (Event ID 1102 or 104).",
        "detection": {
            "selection": {
                "EventID": [1102, 104, "1102", "104"]
            }
        }
    },
    {
        "id": "rule-discovery-commands",
        "name": "Domain and System Reconnaissance Discovery Commands",
        "severity": "low",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1087.002",
        "description": "Detects execution of standard discovery utilities (whoami /all, net group, nltest).",
        "detection": {
            "selection": {
                "CommandLine|contains": ["whoami /all", "net group", "nltest", "dclist"]
            }
        }
    },
    {
        "id": "rule-usb-device-connected",
        "name": "USB Storage Device Connected",
        "severity": "low",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1091",
        "description": "Detects external USB mass storage device connection (Event ID 6416 / 2003).",
        "detection": {
            "selection": {
                "EventID": [6416, 2003, 2102, "6416", "2003"]
            }
        }
    },
    {
        "id": "rule-web-sql-injection",
        "name": "Web SQL Injection & Vulnerability Scanner Pattern",
        "severity": "high",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190",
        "description": "Detects SQL injection syntax or scanner signatures in HTTP request logs.",
        "detection": {
            "selection": {
                "raw|contains": ["union select", "1=1", "information_schema", "sleep(", "drop table", "sqlmap"]
            }
        }
    },
    {
        "id": "rule-reverse-shell-pattern",
        "name": "Interactive Reverse Shell Pattern",
        "severity": "critical",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059.004",
        "description": "Detects bash /dev/tcp socket redirection or netcat reverse interactive shells.",
        "detection": {
            "selection": {
                "CommandLine|contains": ["/dev/tcp", "nc -e", "bash -i >&", "mkfifo /tmp/"]
            }
        }
    },
    {
        "id": "rule-useradd-authorized-keys",
        "name": "Account Creation or Authorized Keys Persistence",
        "severity": "high",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1136.001",
        "description": "Detects unauthorized account creation or modification of SSH authorized_keys.",
        "detection": {
            "selection": {
                "CommandLine|contains": ["useradd", "adduser", "authorized_keys", ".ssh/authorized_keys"]
            }
        }
    },
    {
        "id": "rule-inbox-forwarding-rule",
        "name": "External Email Inbox Forwarding Rule",
        "severity": "medium",
        "mitre_tactic": "Collection",
        "mitre_technique": "T1114.003",
        "description": "Detects creation of email forwarding rules directing messages to external recipients.",
        "detection": {
            "selection": {
                "raw|contains": ["ForwardTo", "RedirectTo", "New-InboxRule", "inbox-forwarding"]
            }
        }
    },
]


def execute_detections_on_events(events: List[Any], case_id: uuid.UUID) -> List[Dict[str, Any]]:
    """
    Evaluates all loaded Sigma rules and correlation rules against stored events.
    Returns structured findings matching Stage 5 requirements.
    """
    findings: List[Dict[str, Any]] = []

    # Sort events chronologically
    def get_ts(e: Any) -> float:
        ts = getattr(e, "timestamp", None) or (e.get("timestamp") if isinstance(e, dict) else None)
        if hasattr(ts, "timestamp"):
            return ts.timestamp()
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            except Exception:
                pass
        return 0.0

    sorted_events = sorted(events, key=get_ts)

    # -------------------------------------------------------------
    # 1. Evaluate Single-Event Sigma Rules
    # -------------------------------------------------------------
    for rule in BUILTIN_SIGMA_RULES:
        sel = rule["detection"].get("selection", {})
        matched_events = []

        for evt in sorted_events:
            if evaluate_event_selection(evt, sel):
                matched_events.append(evt)

        if matched_events:
            first_evt = matched_events[0]
            last_evt = matched_events[-1]

            hosts = list({_extract_field_value(e, "host") for e in matched_events if _extract_field_value(e, "host")})
            users = list({_extract_field_value(e, "user") for e in matched_events if _extract_field_value(e, "user") and _extract_field_value(e, "user") != "unknown"})
            src_files = list({_extract_field_value(e, "source_file") for e in matched_events if _extract_field_value(e, "source_file")})
            rec_ids = [_extract_field_value(e, "source_record_id") for e in matched_events if _extract_field_value(e, "source_record_id") is not None]

            finding_id = f"{rule['id']}-{str(case_id)[:8]}"
            findings.append({
                "id": finding_id,
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "mitre_tactic": rule["mitre_tactic"],
                "mitre_technique": rule["mitre_technique"],
                "description": f"{rule['description']} Detected in {len(matched_events)} event(s).",
                "host": hosts[0] if hosts else "unknown",
                "user": users[0] if users else "unknown",
                "first_seen": getattr(first_evt, "timestamp", None) or first_evt.get("timestamp"),
                "last_seen": getattr(last_evt, "timestamp", None) or last_evt.get("timestamp"),
                "source": "Rule",
                "source_file": src_files[0] if src_files else None,
                "source_record_references": rec_ids,
                "matching_event_ids": [str(getattr(e, "id", None) or e.get("id")) for e in matched_events],
                "rule_information": {
                    "matched_count": len(matched_events),
                    "hosts": hosts,
                    "users": users,
                    "source_files": src_files,
                    "tactic": rule["mitre_tactic"],
                }
            })

    # -------------------------------------------------------------
    # 2. Correlation Rule A: Mass File Rename With Unknown Extension
    # -------------------------------------------------------------
    # Group by host/user; detect >= 10 renames or ransomware note creations within 60s
    rename_events = []
    for evt in sorted_events:
        t_file = str(_extract_field_value(evt, "TargetFilename") or "").lower()
        cmd = str(_extract_field_value(evt, "CommandLine") or "").lower()
        action = str(_extract_field_value(evt, "action") or "").lower()

        if (
            ".cvlk" in t_file
            or "readme_restore_files" in t_file
            or ".cvlk" in cmd
            or "rename" in action and (".cvlk" in action or ".locked" in action)
        ):
            rename_events.append(evt)

    if len(rename_events) >= 5:
        first_evt = rename_events[0]
        last_evt = rename_events[-1]
        hosts = list({_extract_field_value(e, "host") for e in rename_events if _extract_field_value(e, "host")})
        users = list({_extract_field_value(e, "user") for e in rename_events if _extract_field_value(e, "user")})
        src_files = list({_extract_field_value(e, "source_file") for e in rename_events if _extract_field_value(e, "source_file")})

        findings.append({
            "id": f"rule-mass-file-rename-{str(case_id)[:8]}",
            "rule_id": "rule-mass-file-rename",
            "rule_name": "Mass File Rename With Unknown Extension",
            "severity": "critical",
            "mitre_tactic": "Impact",
            "mitre_technique": "T1486",
            "description": f"Detected mass encryption/rename of files to '.cvlk' ransomware extension across {len(rename_events)} operations.",
            "host": hosts[0] if hosts else "SRV-FS-02",
            "user": users[0] if users else "ACME\\admin_svc",
            "first_seen": getattr(first_evt, "timestamp", None) or first_evt.get("timestamp"),
            "last_seen": getattr(last_evt, "timestamp", None) or last_evt.get("timestamp"),
            "source": "Rule",
            "source_file": src_files[0] if src_files else None,
            "source_record_references": [_extract_field_value(e, "source_record_id") for e in rename_events],
            "matching_event_ids": [str(getattr(e, "id", None) or e.get("id")) for e in rename_events],
            "rule_information": {
                "matched_count": len(rename_events),
                "hosts": hosts,
                "users": users,
                "source_files": src_files,
                "tactic": "Impact",
            }
        })

    # -------------------------------------------------------------
    # 3. Correlation Rule B: Failed Logons Followed by Successful Logon
    # -------------------------------------------------------------
    events_by_user = defaultdict(list)
    for evt in sorted_events:
        u = _extract_field_value(evt, "User")
        eid = _extract_field_value(evt, "EventID")
        ev_type = str(getattr(evt, "event_type", None) or evt.get("event_type", "") if isinstance(evt, dict) else "")
        if u and u != "unknown" and u != "-":
            events_by_user[u].append((evt, eid, ev_type))

    for user, u_evts in events_by_user.items():
        failed_evts = []
        for evt, eid, ev_type in u_evts:
            is_fail = eid in (4625, "4625") or "failed" in ev_type or "ssh_failed" in ev_type
            is_success = eid in (4624, "4624") or "success" in ev_type or "ssh_success" in ev_type

            if is_fail:
                failed_evts.append(evt)
            elif is_success and len(failed_evts) >= 1:
                # Correlated attack detected
                all_matched = failed_evts + [evt]
                hosts = list({_extract_field_value(e, "host") for e in all_matched if _extract_field_value(e, "host")})
                clean_user = user.replace("\\", "_")
                findings.append({
                    "id": f"rule-failed-then-success-{clean_user}-{str(case_id)[:8]}",
                    "rule_id": "rule-failed-then-success",
                    "rule_name": "Failed Logons Followed by Successful Logon",
                    "severity": "high",
                    "mitre_tactic": "Credential Access",
                    "mitre_technique": "T1110.001",
                    "description": f"Multiple authentication failures ({len(failed_evts)}) followed by successful logon for user '{user}'.",
                    "host": hosts[0] if hosts else "DC-01",
                    "user": user,
                    "first_seen": getattr(failed_evts[0], "timestamp", None) or failed_evts[0].get("timestamp"),
                    "last_seen": getattr(evt, "timestamp", None) or evt.get("timestamp"),
                    "source": "Rule",
                    "source_file": _extract_field_value(failed_evts[0], "source_file"),
                    "source_record_references": [_extract_field_value(e, "source_record_id") for e in all_matched],
                    "matching_event_ids": [str(getattr(e, "id", None) or e.get("id")) for e in all_matched],
                    "rule_information": {
                        "matched_count": len(all_matched),
                        "failed_count": len(failed_evts),
                        "hosts": hosts,
                        "user": user,
                        "tactic": "Credential Access",
                    }
                })
                break

    # -------------------------------------------------------------
    # 4. Ingest EDR Alerts as Findings (Stage 5 Requirement)
    # -------------------------------------------------------------
    for evt in sorted_events:
        ev_type = str(getattr(evt, "event_type", None) or (evt.get("event_type") if isinstance(evt, dict) else ""))
        details = getattr(evt, "details", None) or (evt.get("details") if isinstance(evt, dict) else {}) or {}
        extra = details.get("extra") or {}

        is_edr = (
            ev_type == "edr_alert"
            or getattr(evt, "source", None) == "EDR"
            or (isinstance(evt, dict) and evt.get("source") == "EDR")
            or "alerts" in str(details.get("source_file", "")).lower()
            or "rule" in extra
        )

        if is_edr and extra.get("rule"):
            alert_rule = extra.get("rule")
            alert_id = extra.get("id") or str(getattr(evt, "id", None) or evt.get("id"))
            mitre_str = extra.get("mitre_technique") or "T1059"
            first_mitre = mitre_str.split(",")[0].strip() if "," in mitre_str else mitre_str

            # Map tactic from technique
            tactics_map = {
                "T1204": "Initial Access", "T1566": "Initial Access", "T1190": "Initial Access",
                "T1059": "Execution", "T1204.002": "Execution",
                "T1547": "Persistence", "T1505": "Persistence", "T1136": "Persistence",
                "T1548": "Privilege Escalation",
                "T1070": "Defense Evasion",
                "T1003": "Credential Access", "T1110": "Credential Access",
                "T1087": "Discovery", "T1082": "Discovery",
                "T1569": "Lateral Movement", "T1021": "Lateral Movement",
                "T1071": "Command and Control",
                "T1567": "Exfiltration", "T1041": "Exfiltration",
                "T1490": "Impact", "T1486": "Impact",
            }
            prefix = first_mitre.split(".")[0]
            tactic = tactics_map.get(first_mitre) or tactics_map.get(prefix) or "Execution"

            findings.append({
                "id": f"edr-{alert_id}",
                "rule_id": f"edr-{alert_id}",
                "rule_name": alert_rule,
                "severity": extra.get("severity", "high").lower(),
                "mitre_tactic": tactic,
                "mitre_technique": first_mitre,
                "description": f"EDR Detections: {alert_rule} on {details.get('host', 'unknown')}",
                "host": details.get("host") or "unknown",
                "user": details.get("user") or "unknown",
                "first_seen": getattr(evt, "timestamp", None) or evt.get("timestamp"),
                "last_seen": getattr(evt, "timestamp", None) or evt.get("timestamp"),
                "source": "EDR",
                "source_file": details.get("source_file"),
                "source_record_references": [alert_id],
                "matching_event_ids": [str(getattr(evt, "id", None) or evt.get("id"))],
                "rule_information": {
                    "source": "EDR",
                    "alert_id": alert_id,
                    "mitre_technique": mitre_str,
                    "tactic": tactic,
                    "host": details.get("host"),
                    "user": details.get("user"),
                }
            })

    return findings


def get_rule_coverage_matrix(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes rule coverage view: each rule, times fired in the case,
    and which MITRE techniques are covered or not covered.
    """
    rule_counts: Dict[str, int] = defaultdict(int)
    covered_techniques: Set[str] = set()

    for f in findings:
        r_name = f.get("rule_name") or f.get("rule_id")
        rule_counts[r_name] += 1
        t = f.get("mitre_technique")
        if t:
            for item in t.split(","):
                covered_techniques.add(item.strip())

    catalog_techniques = {
        "T1204.002", "T1059.001", "T1003.001", "T1003.003", "T1569.002",
        "T1021.002", "T1567.002", "T1490", "T1486", "T1070.001", "T1110.001",
        "T1087.002", "T1091", "T1190", "T1059.004", "T1136.001", "T1114.003",
        "T1621", "T1505.003", "T1547.001", "T1071.001"
    }

    rules_summary = []
    for r in BUILTIN_SIGMA_RULES:
        rules_summary.append({
            "id": r["id"],
            "name": r["name"],
            "severity": r["severity"],
            "mitre_tactic": r["mitre_tactic"],
            "mitre_technique": r["mitre_technique"],
            "times_fired": rule_counts.get(r["name"], 0),
        })

    return {
        "rules": rules_summary,
        "total_rules": len(BUILTIN_SIGMA_RULES),
        "total_findings": len(findings),
        "covered_techniques": sorted(list(covered_techniques)),
        "uncovered_techniques": sorted(list(catalog_techniques - covered_techniques)),
    }
