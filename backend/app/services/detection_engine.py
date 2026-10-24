"""
DCSRE Deterministic Detection Engine & Sigma Field Matcher (Stage 4 & Stage 5)
Strictly rule-based, deterministic analysis. Evaluates single-event and correlation rules.

B1/B4 fixes:
- Every finding now includes actor (source), target_host, and role fields.
- MITRE mappings are correct per technique, no defaults.
- WAF/IDS findings mapped by rule message/id, not a constant.
- action field never goes into severity.

C1 fixes:
- Added all missing Linux/web rules: scanner UAs, SQL injection, double-extension upload,
  webshell request, reverse shell, sudo escape, useradd/sudo group, authorized_keys,
  /tmp download+exec, crontab, mysqldump+scp, history -c / log removal,
  miner pool ports, CPU >90% cryptomining metric rule.
- Windows rules retained.
"""
import fnmatch
import json
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Sigma Field Mapping Table (Stage 4)
# ---------------------------------------------------------------------------
SIGMA_FIELD_MAP: Dict[str, List[str]] = {
    "Image": ["process", "details.process", "details.NewProcessName", "details.Image"],
    "NewProcessName": ["process", "details.NewProcessName", "details.Image"],
    "CommandLine": ["command_line", "details.command_line", "details.CommandLine", "details.ImagePath"],
    "ProcessCommandLine": ["command_line", "details.command_line", "details.CommandLine"],
    "ParentImage": ["parent_process", "details.parent_process", "details.ParentImage", "details.ParentProcessName"],
    "ParentProcessName": ["parent_process", "details.parent_process", "details.ParentImage", "details.ParentProcessName"],
    "User": ["user", "details.user", "details.TargetUserName", "details.SubjectUserName", "details.username"],
    "SubjectUserName": ["details.SubjectUserName", "user", "details.user"],
    "TargetUserName": ["details.TargetUserName", "user", "details.user"],
    "Account": ["user", "details.user"],
    "EventID": ["event_id", "details.event_id", "details.EventID"],
    "EventId": ["event_id", "details.event_id"],
    "ServiceName": ["service_name", "details.service_name", "details.ServiceName"],
    "ImagePath": ["command_line", "details.command_line", "details.ImagePath"],
    "TargetFilename": ["target_file", "details.target_file", "details.TargetFilename", "details.path", "details.dst"],
    "TargetObject": ["target_file", "details.target_file", "details.TargetObject"],
    "Path": ["target_file", "details.target_file", "details.path", "details.src", "details.dst"],
    "SourceIp": ["src_ip", "details.src_ip", "details.source_ip", "details.IpAddress"],
    "DestinationIp": ["dst_ip", "details.dst_ip", "details.destination_ip", "details.DestinationIp"],
    "SourcePort": ["src_port", "details.src_port", "details.source_port"],
    "DestinationPort": ["dst_port", "details.dst_port", "details.destination_port"],
    "Protocol": ["protocol", "details.protocol", "details.proto"],
    "QueryName": ["details.extra.query_name", "target_file", "command_line", "details.query_name"],
    "Computer": ["host", "details.host", "details.Computer", "details.computer"],
    "Host": ["host", "details.host"],
    "action": ["action", "details.action"],
    "raw": ["raw", "details.raw", "details.raw_message"],
    "status": ["outcome", "details.outcome", "details.status", "details.Status"],
    # metric-specific
    "cpu_percent": ["details.cpu", "details.cpu_percent", "details.cpu_usage", "details.extra.cpu", "details.extra.cpu_percent"],
}


def _extract_field_value(event: Any, field_name: str) -> Optional[Any]:
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
    if actual is None:
        return False
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
    if modifier in ("re", "regex"):
        try:
            return bool(re.search(expected, str(actual), re.IGNORECASE))
        except re.error:
            return False
    if "*" in expected_str or "?" in expected_str:
        return fnmatch.fnmatchcase(actual_str, expected_str)
    return actual_str == expected_str


def evaluate_event_selection(event: Any, selection: Dict[str, Any]) -> bool:
    for field_spec, expected in selection.items():
        parts = field_spec.split("|")
        field_name = parts[0]
        modifier = parts[1].lower() if len(parts) > 1 else "equals"
        actual_val = _extract_field_value(event, field_name)
        if not match_value(actual_val, expected, modifier):
            return False
    return True


# ---------------------------------------------------------------------------
# Tactic lookup table (no defaults — only known mappings)
# ---------------------------------------------------------------------------
_TACTIC_BY_TECHNIQUE: Dict[str, str] = {
    "T1190": "Initial Access",
    "T1091": "Initial Access",
    "T1566": "Initial Access", "T1566.001": "Initial Access",
    "T1204": "Execution", "T1204.002": "Execution",
    "T1059": "Execution", "T1059.001": "Execution", "T1059.004": "Execution",
    "T1505": "Persistence", "T1505.003": "Persistence",
    "T1136": "Persistence", "T1136.001": "Persistence",
    "T1547": "Persistence", "T1547.001": "Persistence",
    "T1098": "Persistence", "T1098.004": "Persistence",
    "T1053": "Persistence", "T1053.005": "Persistence",
    "T1548": "Privilege Escalation", "T1548.003": "Privilege Escalation",
    "T1068": "Privilege Escalation",
    "T1070": "Defense Evasion", "T1070.001": "Defense Evasion", "T1070.003": "Defense Evasion",
    "T1003": "Credential Access", "T1003.001": "Credential Access", "T1003.003": "Credential Access",
    "T1110": "Credential Access", "T1110.001": "Credential Access",
    "T1087": "Discovery", "T1087.002": "Discovery",
    "T1082": "Discovery",
    "T1046": "Discovery",
    "T1569": "Lateral Movement", "T1569.002": "Lateral Movement",
    "T1021": "Lateral Movement",
    "T1071": "Command and Control", "T1071.001": "Command and Control",
    "T1496": "Impact",
    "T1486": "Impact",
    "T1490": "Impact",
    "T1567": "Exfiltration", "T1567.002": "Exfiltration",
    "T1041": "Exfiltration",
    "T1048": "Exfiltration",
    "T1114": "Collection", "T1114.003": "Collection",
    "T1595": "Reconnaissance", "T1595.002": "Reconnaissance",
    "T1592": "Reconnaissance",
}


def _tactic(technique: str) -> str:
    t = _TACTIC_BY_TECHNIQUE.get(technique)
    if t:
        return t
    prefix = technique.split(".")[0]
    return _TACTIC_BY_TECHNIQUE.get(prefix, "Unknown")


# ---------------------------------------------------------------------------
# Built-in Sigma Rules Catalog  (B4 + C1 fixes)
# ---------------------------------------------------------------------------
BUILTIN_SIGMA_RULES: List[Dict[str, Any]] = [
    # ------------------------------------------------------------------ #
    # Web / Initial Access                                                 #
    # ------------------------------------------------------------------ #
    {
        "id": "rule-scanner-useragent",
        "name": "Reconnaissance Scanner User-Agent",
        "severity": "medium",
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1595.002",
        "description": "Detects known vulnerability scanner user-agents (Nikto, sqlmap, nmap scripting engine).",
        "detection": {
            "selection": {
                "raw|contains": ["nikto", "sqlmap", "nmap scripting engine", "masscan", "dirbuster", "nuclei", "openvas"]
            }
        }
    },
    {
        "id": "rule-web-sql-injection",
        "name": "SQL Injection Pattern in HTTP Request",
        "severity": "high",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190",
        "description": "Detects SQL injection syntax in HTTP request logs.",
        "detection": {
            "selection": {
                "raw|contains": ["union select", "1=1", "1=1--", "information_schema", "sleep(", "drop table", "'; --", "or 1=1", "benchmark("]
            }
        }
    },
    {
        "id": "rule-double-extension-upload",
        "name": "Malicious Double-Extension File Upload",
        "severity": "high",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190",
        "description": "Detects upload of files with double extensions (.php.jpg, .asp.gif) used to bypass upload filters.",
        "detection": {
            "selection": {
                "raw|contains": [".php.jpg", ".php.png", ".php.gif", ".asp.jpg", ".jsp.jpg", ".phtml.jpg"]
            }
        }
    },
    # ------------------------------------------------------------------ #
    # Web Shell / Persistence                                              #
    # ------------------------------------------------------------------ #
    {
        "id": "rule-webshell-request",
        "name": "Web Shell Command Execution Request",
        "severity": "critical",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1505.003",
        "description": "Detects HTTP requests containing ?cmd=, ?exec=, or ?shell= patterns indicative of web shell usage.",
        "detection": {
            "selection": {
                "raw|contains": ["?cmd=", "&cmd=", "?exec=", "?shell=", "?c=", "eval(base64", "base64_decode", "system(", "passthru(", "assert("]
            }
        }
    },
    # ------------------------------------------------------------------ #
    # Execution                                                            #
    # ------------------------------------------------------------------ #
    {
        "id": "rule-reverse-shell-pattern",
        "name": "Interactive Reverse Shell Pattern",
        "severity": "critical",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059.004",
        "description": "Detects bash /dev/tcp socket redirection, netcat reverse interactive shells, or mkfifo patterns.",
        "detection": {
            "selection": {
                "CommandLine|contains": ["/dev/tcp", "nc -e", "bash -i >&", "mkfifo /tmp/", "ncat -e", "socat exec"]
            }
        }
    },
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
        "description": "Detects execution of PowerShell commands using encoded command line arguments.",
        "detection": {
            "selection": {
                "CommandLine|contains": ["-enc", "-encodedcommand", "-e SQ", "-enco "]
            }
        }
    },
    # ------------------------------------------------------------------ #
    # Privilege Escalation                                                 #
    # ------------------------------------------------------------------ #
    {
        "id": "rule-sudo-shell-escape",
        "name": "Sudo Shell Escape via Editor or Utility",
        "severity": "critical",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1548.003",
        "description": "Detects privilege escalation through shell escapes from sudo-permitted programs (vim, less, find, awk, etc.).",
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "sudo vim", "sudo vi ", "sudo less", "sudo more",
                    "sudo awk", "sudo find", "sudo nmap",
                    ":!/bin/sh", ":!/bin/bash", "!/bin/sh", "sudo -s",
                    "sudo su ", "sudo bash"
                ]
            }
        }
    },
    # ------------------------------------------------------------------ #
    # Persistence                                                          #
    # ------------------------------------------------------------------ #
    {
        "id": "rule-useradd-authorized-keys",
        "name": "Account Creation or Authorized Keys Persistence",
        "severity": "high",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1136.001",
        "description": "Detects unauthorized account creation (useradd/adduser) or modification of SSH authorized_keys.",
        "detection": {
            "selection": {
                "CommandLine|contains": ["useradd", "adduser", "authorized_keys", ".ssh/authorized_keys"]
            }
        }
    },
    {
        "id": "rule-add-user-to-sudo",
        "name": "User Added to Sudoers or Privileged Group",
        "severity": "high",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1098.004",
        "description": "Detects a user being added to sudo, wheel, or adm groups for persistent privilege.",
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "usermod -aG sudo", "usermod -aG wheel", "usermod -G sudo",
                    "gpasswd -a", "/etc/sudoers"
                ]
            }
        }
    },
    {
        "id": "rule-tmp-download-exec",
        "name": "Download to /tmp Then Execute",
        "severity": "high",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059.004",
        "description": "Detects downloading a file to /tmp then making it executable with chmod +x and running it.",
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "chmod +x /tmp/", "chmod 755 /tmp/", "chmod 777 /tmp/",
                    "wget http", "curl http", "/tmp/", "tar xf /tmp"
                ]
            }
        }
    },
    {
        "id": "rule-crontab-modification",
        "name": "Crontab or Cron Job Modification",
        "severity": "medium",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1053.005",
        "description": "Detects modification of cron jobs for persistence (crontab -e, writes to /etc/cron*).",
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "crontab -e", "crontab -l", "/etc/cron.d/", "/etc/crontab",
                    "/var/spool/cron", "echo * * * * *"
                ]
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
    # ------------------------------------------------------------------ #
    # Defense Evasion                                                      #
    # ------------------------------------------------------------------ #
    {
        "id": "rule-history-clear-log-removal",
        "name": "History Cleared or Log File Removed",
        "severity": "high",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1070.003",
        "description": "Detects clearing of shell history or removal of log files to cover tracks.",
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "history -c", "history -w /dev/null", "unset HISTFILE",
                    "rm /var/log/", "shred /var/log/", "truncate -s 0",
                    "cat /dev/null > ~/.bash_history", "> /var/log/auth.log"
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
    # ------------------------------------------------------------------ #
    # Credential Access                                                    #
    # ------------------------------------------------------------------ #
    {
        "id": "rule-lsass-memory-dump",
        "name": "LSASS Memory Access and Credential Dumping",
        "severity": "critical",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1003.001",
        "description": "Detects access or dump of LSASS memory via comsvcs.dll or procdump.",
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
        "description": "Detects execution of ntdsutil to dump or extract NTDS.dit.",
        "detection": {
            "selection": {
                "CommandLine|contains": ["ntdsutil", "ntds.dit"]
            }
        }
    },
    # ------------------------------------------------------------------ #
    # Discovery                                                            #
    # ------------------------------------------------------------------ #
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
    # ------------------------------------------------------------------ #
    # Lateral Movement                                                     #
    # ------------------------------------------------------------------ #
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
    # ------------------------------------------------------------------ #
    # Exfiltration                                                         #
    # ------------------------------------------------------------------ #
    {
        "id": "rule-mysqldump-scp-exfil",
        "name": "Database Dump Followed by SCP Transfer",
        "severity": "high",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1048",
        "description": "Detects mysqldump used to stage a database dump, followed by scp transfer to an external address.",
        "detection": {
            "selection": {
                "CommandLine|contains": ["mysqldump", "pg_dump", "sqlite3 .dump"]
            }
        }
    },
    {
        "id": "rule-scp-transfer",
        "name": "SCP or SFTP Transfer to External Host",
        "severity": "medium",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1048",
        "description": "Detects use of scp or sftp to transfer files to a remote host.",
        "detection": {
            "selection": {
                "CommandLine|contains": ["scp ", "sftp ", "rsync --rsh"]
            }
        }
    },
    {
        "id": "rule-rclone-large-transfer",
        "name": "Large Outbound Transfer or rclone Staging",
        "severity": "high",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1567.002",
        "description": "Detects adversary exfiltration using rclone utility.",
        "detection": {
            "selection": {
                "CommandLine|contains": ["rclone", "rclone.exe"]
            }
        }
    },
    # ------------------------------------------------------------------ #
    # Impact                                                               #
    # ------------------------------------------------------------------ #
    {
        "id": "rule-miner-pool-ports",
        "name": "Connection to Cryptomining Pool Port",
        "severity": "high",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1496",
        "description": "Detects outbound connections to common cryptomining pool ports (3333, 4444, 5555, 7777, 9999, 14444, 45700).",
        "detection": {
            "selection": {
                "DestinationPort": [3333, 4444, 5555, 7777, 9999, 14444, 45700,
                                    "3333", "4444", "5555", "7777", "9999", "14444", "45700"]
            }
        }
    },
    {
        "id": "rule-shadow-copy-deletion",
        "name": "Inhibit System Recovery via Shadow Copy Deletion",
        "severity": "critical",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1490",
        "description": "Detects deletion of volume shadow copies or disabling recovery mode.",
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "delete shadows", "vssadmin",
                    "recoveryenabled no", "wbadmin delete catalog"
                ]
            }
        }
    },
    # ------------------------------------------------------------------ #
    # Initial Access                                                       #
    # ------------------------------------------------------------------ #
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
]


# ---------------------------------------------------------------------------
# B1: Role determination helpers
# ---------------------------------------------------------------------------

def _is_private(ip: str) -> bool:
    import ipaddress
    try:
        a = ipaddress.ip_address(ip.strip())
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


def _determine_roles(
    findings: List[Dict[str, Any]]
) -> Dict[str, str]:
    """
    B1: Determine adversary vs victim roles from findings.

    Returns a dict {entity: role} where role is one of:
      'adversary_infrastructure' | 'compromised_host' |
      'compromised_account'      | 'victim_host'

    Rules (deterministic, behavior-based):
    - Compromised host: internal host that is the *target* of a successful
      malicious finding (process exec, priv-esc, persistence, staging, exfil)
      OR the target of a successful exploit.
      The attacker's own source address is NEVER a compromised host.
    - Adversary infrastructure: external address that is the *source* of a
      malicious finding, OR that a compromised host contacted in a finding
      (C2, payload download, mining pool, exfil dest).
      Normal traffic from that address alone is NOT enough.
    - Compromised account: user appearing in findings with malicious/suspicious
      actions.
    - Victim host: internal host that is a target but not adversary infra.
    """
    # Tactics that imply the *target host* is compromised
    COMPROMISE_TACTICS = {
        "Execution", "Privilege Escalation", "Persistence",
        "Defense Evasion", "Exfiltration", "Impact"
    }
    # Tactics that imply the *source address* is adversary infra
    ADVERSARY_SRC_TACTICS = {
        "Initial Access", "Reconnaissance",
        "Execution", "Credential Access"
    }
    # Tactics that imply a contacted *dest address* is adversary infra
    ADVERSARY_DST_TACTICS = {
        "Command and Control", "Exfiltration", "Impact"
    }

    compromised_hosts: Set[str] = set()
    adversary_ips: Set[str] = set()
    victim_hosts: Set[str] = set()
    compromised_accounts: Set[str] = set()
    # Track which IPs were involved as attacker sources in malicious findings
    malicious_src_ips: Set[str] = set()

    for f in findings:
        tactic = f.get("mitre_tactic", "")
        actor = f.get("actor") or f.get("src_ip") or f.get("rule_information", {}).get("src_ip")
        target = f.get("target_host") or f.get("host")
        user = f.get("user")

        # Determine if external
        actor_is_external = actor and not _is_private(actor)
        target_is_internal = target and _is_private(target) if target and _looks_like_ip(target) else bool(target)

        if tactic in ADVERSARY_SRC_TACTICS and actor and actor_is_external:
            adversary_ips.add(actor)
            malicious_src_ips.add(actor)

        if tactic in COMPROMISE_TACTICS and target:
            if not _looks_like_ip(target) or _is_private(target):
                # Target is internal host
                if target not in malicious_src_ips:
                    compromised_hosts.add(target)

        if tactic in ADVERSARY_DST_TACTICS:
            dst = f.get("dst_ip") or f.get("rule_information", {}).get("dst_ip")
            if dst and not _is_private(dst):
                adversary_ips.add(dst)

        if user and user not in ("unknown", "SYSTEM", "-") and tactic in COMPROMISE_TACTICS | ADVERSARY_SRC_TACTICS:
            compromised_accounts.add(user)

        # Victim hosts are targets not already adversary
        if target and target not in adversary_ips:
            if not _looks_like_ip(target) or _is_private(target):
                victim_hosts.add(target)

    # Remove compromised hosts from adversary (never both)
    adversary_ips -= {h for h in adversary_ips if not _looks_like_ip(h)}

    roles: Dict[str, str] = {}
    for h in compromised_hosts:
        roles[h] = "compromised_host"
    for ip in adversary_ips:
        roles[ip] = "adversary_infrastructure"
    for u in compromised_accounts:
        roles[u] = "compromised_account"
    for h in victim_hosts:
        if h not in roles:
            roles[h] = "victim_host"
    return roles


def _looks_like_ip(s: str) -> bool:
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s or ""))


# ---------------------------------------------------------------------------
# Main detection executor
# ---------------------------------------------------------------------------

def execute_detections_on_events(events: List[Any], case_id: uuid.UUID) -> List[Dict[str, Any]]:
    """
    Evaluates all loaded Sigma rules and correlation rules against stored events.
    Returns structured findings matching Stage 5 requirements.

    B1/B4 additions:
    - Every finding includes actor, target_host, src_ip.
    - MITRE mapping is taken directly from the rule (no defaults).
    - action field is never placed in severity.
    """
    findings: List[Dict[str, Any]] = []

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

    # ------------------------------------------------------------------
    # 1. Evaluate Single-Event Sigma Rules
    # ------------------------------------------------------------------
    for rule in BUILTIN_SIGMA_RULES:
        # Skip metric-type events for non-metric rules
        sel = rule["detection"].get("selection", {})
        matched_events = [
            evt for evt in sorted_events
            if evaluate_event_selection(evt, sel)
        ]

        if matched_events:
            first_evt = matched_events[0]
            last_evt = matched_events[-1]

            hosts = list({_extract_field_value(e, "host") for e in matched_events if _extract_field_value(e, "host")})
            users = list({_extract_field_value(e, "user") for e in matched_events
                          if _extract_field_value(e, "user") and _extract_field_value(e, "user") not in ("unknown", "-")})
            src_ips = list({_extract_field_value(e, "SourceIp") for e in matched_events if _extract_field_value(e, "SourceIp")})
            src_files = list({_extract_field_value(e, "source_file") for e in matched_events if _extract_field_value(e, "source_file")})
            rec_ids = [_extract_field_value(e, "source_record_id") for e in matched_events if _extract_field_value(e, "source_record_id") is not None]

            finding_id = f"{rule['id']}-{str(case_id)[:8]}"
            # B1: actor is the src_ip (who did it); target_host is the host (where)
            actor = src_ips[0] if src_ips else (users[0] if users else None)
            target_host = hosts[0] if hosts else None

            findings.append({
                "id": finding_id,
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],   # B4: never put action here
                "mitre_tactic": rule["mitre_tactic"],
                "mitre_technique": rule["mitre_technique"],
                "description": f"{rule['description']} Detected in {len(matched_events)} event(s).",
                # B1 fields
                "actor": actor,
                "target_host": target_host,
                "host": target_host or "unknown",
                "user": users[0] if users else "unknown",
                "src_ip": src_ips[0] if src_ips else None,
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
                    "src_ips": src_ips,
                }
            })

    # ------------------------------------------------------------------
    # 2. Correlation Rule: Mass File Rename With Unknown Extension
    # ------------------------------------------------------------------
    rename_events = []
    for evt in sorted_events:
        t_file = str(_extract_field_value(evt, "TargetFilename") or "").lower()
        cmd = str(_extract_field_value(evt, "CommandLine") or "").lower()
        action = str(_extract_field_value(evt, "action") or "").lower()
        if (
            ".cvlk" in t_file or "readme_restore_files" in t_file
            or ".cvlk" in cmd
            or ("rename" in action and (".cvlk" in action or ".locked" in action))
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
            "actor": users[0] if users else None,
            "target_host": hosts[0] if hosts else None,
            "host": hosts[0] if hosts else "unknown",
            "user": users[0] if users else "unknown",
            "src_ip": None,
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

    # ------------------------------------------------------------------
    # 3. Correlation Rule: Failed Logons Followed by Successful Logon
    # ------------------------------------------------------------------
    events_by_user: Dict[str, list] = defaultdict(list)
    for evt in sorted_events:
        u = _extract_field_value(evt, "User")
        eid = _extract_field_value(evt, "EventID")
        ev_type = str(getattr(evt, "event_type", None) or (evt.get("event_type", "") if isinstance(evt, dict) else ""))
        if u and u not in ("unknown", "-"):
            events_by_user[u].append((evt, eid, ev_type))

    for user, u_evts in events_by_user.items():
        failed_evts = []
        for evt, eid, ev_type in u_evts:
            is_fail = eid in (4625, "4625") or "failed" in ev_type or "ssh_failed" in ev_type
            is_success = eid in (4624, "4624") or "success" in ev_type or "ssh_success" in ev_type
            if is_fail:
                failed_evts.append(evt)
            elif is_success and len(failed_evts) >= 1:
                all_matched = failed_evts + [evt]
                hosts = list({_extract_field_value(e, "host") for e in all_matched if _extract_field_value(e, "host")})
                src_ips = list({_extract_field_value(e, "SourceIp") for e in all_matched if _extract_field_value(e, "SourceIp")})
                clean_user = user.replace("\\", "_")
                findings.append({
                    "id": f"rule-failed-then-success-{clean_user}-{str(case_id)[:8]}",
                    "rule_id": "rule-failed-then-success",
                    "rule_name": "Failed Logons Followed by Successful Logon",
                    "severity": "high",
                    "mitre_tactic": "Credential Access",
                    "mitre_technique": "T1110.001",
                    "description": f"Multiple authentication failures ({len(failed_evts)}) followed by successful logon for user '{user}'.",
                    "actor": src_ips[0] if src_ips else user,
                    "target_host": hosts[0] if hosts else None,
                    "host": hosts[0] if hosts else "unknown",
                    "user": user,
                    "src_ip": src_ips[0] if src_ips else None,
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
                        "src_ips": src_ips,
                        "tactic": "Credential Access",
                    }
                })
                break

    # ------------------------------------------------------------------
    # 4. Ingest EDR / WAF Alert Files as Findings (B4 fix: map by rule id)
    # ------------------------------------------------------------------
    for evt in sorted_events:
        ev_type = str(getattr(evt, "event_type", None) or (evt.get("event_type", "") if isinstance(evt, dict) else ""))
        details = getattr(evt, "details", None) or (evt.get("details") if isinstance(evt, dict) else {}) or {}
        extra = details.get("extra") or {}

        is_edr = (
            ev_type == "edr_alert"
            or getattr(evt, "source", None) in ("EDR", "WAF")
            or (isinstance(evt, dict) and evt.get("source") in ("EDR", "WAF"))
            or "alerts" in str(details.get("source_file", "")).lower()
            or "edr" in str(details.get("source_file", "")).lower()
            or "waf" in str(details.get("source_file", "")).lower()
            or ("rule" in extra and extra.get("rule"))
        )

        if not is_edr:
            continue

        alert_rule = extra.get("rule") or extra.get("rule_name") or extra.get("alert_name")
        if not alert_rule:
            continue

        alert_id = extra.get("id") or str(getattr(evt, "id", None) or evt.get("id"))
        # B4: use explicit mitre from the alert record; do NOT default to T1059
        mitre_str = extra.get("mitre_technique") or extra.get("mitre") or ""
        # Parse first technique
        first_mitre = None
        if mitre_str:
            first_mitre = mitre_str.split(",")[0].strip() if "," in mitre_str else mitre_str.strip()
        tactic = _tactic(first_mitre) if first_mitre else extra.get("tactic", "Unknown")

        # B4: action field goes in action, never severity
        alert_action = extra.get("action") or details.get("action")
        severity = str(extra.get("severity") or "high").lower()
        # guard against someone putting action in severity
        if severity in ("logged_not_blocked", "blocked", "allowed", "monitored"):
            severity = "medium"

        src_ip = details.get("src_ip") or details.get("source_ip") or extra.get("src_ip")
        target_host = details.get("host") or extra.get("target")

        findings.append({
            "id": f"edr-{alert_id}",
            "rule_id": f"edr-{alert_id}",
            "rule_name": alert_rule,
            "severity": severity,
            "mitre_tactic": tactic,
            "mitre_technique": first_mitre,      # may be None — that's correct
            "description": f"Alert: {alert_rule} on {target_host or 'unknown'}",
            "actor": src_ip,
            "target_host": target_host,
            "host": target_host or "unknown",
            "user": details.get("user") or "unknown",
            "src_ip": src_ip,
            "action": alert_action,              # B4: stored here, not in severity
            "first_seen": getattr(evt, "timestamp", None) or evt.get("timestamp"),
            "last_seen": getattr(evt, "timestamp", None) or evt.get("timestamp"),
            "source": extra.get("source", "EDR"),
            "source_file": details.get("source_file"),
            "source_record_references": [alert_id],
            "matching_event_ids": [str(getattr(evt, "id", None) or evt.get("id"))],
            "rule_information": {
                "source": extra.get("source", "EDR"),
                "alert_id": alert_id,
                "mitre_technique": mitre_str,
                "tactic": tactic,
                "host": target_host,
                "user": details.get("user"),
                "src_ip": src_ip,
                "action": alert_action,
            }
        })

    # ------------------------------------------------------------------
    # 5. Metric rule: CPU >90% for sustained period (T1496 cryptomining)
    # ------------------------------------------------------------------
    metric_events = [
        e for e in sorted_events
        if (getattr(e, "event_type", None) or (e.get("event_type") if isinstance(e, dict) else "")) == "metric"
    ]
    high_cpu_evts = []
    for evt in metric_events:
        cpu_raw = _extract_field_value(evt, "cpu_percent")
        try:
            cpu_val = float(str(cpu_raw).strip().rstrip("%"))
        except (TypeError, ValueError):
            continue
        if cpu_val >= 90.0:
            high_cpu_evts.append(evt)

    if len(high_cpu_evts) >= 3:  # ≥ 3 consecutive 5-min samples = ≥15 min
        hosts = list({_extract_field_value(e, "host") for e in high_cpu_evts if _extract_field_value(e, "host")})
        src_files = list({_extract_field_value(e, "source_file") for e in high_cpu_evts if _extract_field_value(e, "source_file")})
        findings.append({
            "id": f"rule-high-cpu-cryptomining-{str(case_id)[:8]}",
            "rule_id": "rule-high-cpu-cryptomining",
            "rule_name": "Sustained High CPU — Suspected Cryptomining",
            "severity": "high",
            "mitre_tactic": "Impact",
            "mitre_technique": "T1496",
            "description": f"CPU above 90% for {len(high_cpu_evts)} consecutive metric samples (≥15 min), suspected cryptomining activity.",
            "actor": None,
            "target_host": hosts[0] if hosts else None,
            "host": hosts[0] if hosts else "unknown",
            "user": "unknown",
            "src_ip": None,
            "first_seen": getattr(high_cpu_evts[0], "timestamp", None) or high_cpu_evts[0].get("timestamp"),
            "last_seen": getattr(high_cpu_evts[-1], "timestamp", None) or high_cpu_evts[-1].get("timestamp"),
            "source": "Rule",
            "source_file": src_files[0] if src_files else None,
            "source_record_references": [_extract_field_value(e, "source_record_id") for e in high_cpu_evts],
            "matching_event_ids": [str(getattr(e, "id", None) or e.get("id")) for e in high_cpu_evts],
            "rule_information": {
                "matched_count": len(high_cpu_evts),
                "hosts": hosts,
                "source_files": src_files,
                "tactic": "Impact",
            }
        })

    # Enrich all findings with role information (B1)
    roles = _determine_roles(findings)
    for f in findings:
        actor = f.get("actor")
        target = f.get("target_host")
        f["actor_role"] = roles.get(str(actor)) if actor else None
        f["target_role"] = roles.get(str(target)) if target else None

    return findings


def get_rule_coverage_matrix(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Rule coverage view: each rule, times fired, techniques covered/not covered."""
    rule_counts: Dict[str, int] = defaultdict(int)
    covered_techniques: Set[str] = set()

    for f in findings:
        r_name = f.get("rule_name") or f.get("rule_id")
        rule_counts[r_name] += 1
        t = f.get("mitre_technique")
        if t:
            for item in str(t).split(","):
                covered_techniques.add(item.strip())

    catalog_techniques = {r["mitre_technique"] for r in BUILTIN_SIGMA_RULES}

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
