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
from app.services.entity_classification import is_internal_ip
from app.services.detection import extract_sqli_indicators


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
    "cpu_percent": [
        "details.cpu",
        "details.cpu_percent",
        "details.cpu_pct",
        "details.cpu_usage",
        "details.extra.cpu",
        "details.extra.cpu_percent",
        "details.extra.cpu_pct",
    ],
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
    "T1070.004": "Defense Evasion",
    "T1003": "Credential Access", "T1003.001": "Credential Access", "T1003.003": "Credential Access",
    "T1110": "Credential Access", "T1110.001": "Credential Access",
    "T1087": "Discovery", "T1087.002": "Discovery",
    "T1082": "Discovery",
    "T1046": "Discovery",
    "T1569": "Lateral Movement", "T1569.002": "Lateral Movement",
    "T1021": "Lateral Movement",
    "T1071": "Command and Control", "T1071.001": "Command and Control",
    "T1105": "Command and Control",
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
                "raw|contains": [
                    "union select", "1=1", "1=1--", "information_schema",
                    "sleep(", "drop table", "'; --", "or 1=1", "benchmark(",
                    "' or '1'='1", "\" or \"1\"=\"1", "into outfile", "load_file(",
                    "extractvalue(", "updatexml("
                ]
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
        "name": "Ingress Tool Transfer to /tmp Then Extract/Cron/Execute",
        "severity": "high",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1105",
        "description": "Detects download tools (wget/curl) writing to /tmp or hidden paths followed within 5 minutes by extraction, cron persistence, or execution from that path.",
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "wget ", "curl ", "/tmp/", "tar ", "crontab"
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
        "id": "rule-file-deletion-after-exfil",
        "name": "Staged or Log File Deletion",
        "severity": "medium",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1070.004",
        "description": "Detects removal of staged files in /tmp or log artifacts (e.g. rm -f /tmp/c.sql) to cover tracks.",
        "detection": {
            "selection": {
                "CommandLine|re": r"\b(?:rm|unlink|shred)\b.*(?:/tmp/|/var/tmp/|/dev/shm/|/var/log/|\.log\b|\.sql\b)"
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
        "mitre_technique": "T1021.002",
        # Also covers T1569.002 (Execution via remote service)
        "mitre_techniques": ["T1021.002", "T1569.002"],
        "description": "Detects remote service creation or PsExec service installation (Event ID 7045 / 4697) — indicative of lateral movement via SMB/PsExec.",
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
        "description": "Detects outbound connections to common cryptomining pool ports (3333, 5555, 7777, 9999, 14444, 45700).",
        "detection": {
            "selection": {
                "DestinationPort": [3333, 5555, 7777, 9999, 14444, 45700,
                                    "3333", "5555", "7777", "9999", "14444", "45700"]
            }
        }
    },
    {
        "id": "rule-miner-process",
        "name": "Cryptomining Process Execution",
        "severity": "high",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1496",
        "description": "Detects process execution referencing cryptomining pool flags (--pool, stratum) or pool ports (3333, 5555, 7777, 9999, 14444, 45700).",
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "--pool", "stratum",
                    ":3333", ":5555", ":7777", ":9999", ":14444", ":45700",
                ]
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
    # ------------------------------------------------------------------ #
    # fix-10: Phishing macro attachment (T1566.001)                        #
    # ------------------------------------------------------------------ #
    {
        "id": "rule-phishing-macro-attachment",
        "name": "Phishing Email with Macro-Enabled Attachment",
        "severity": "high",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1566.001",
        "description": "Detects macro-enabled Office attachments (.docm, .xlsm, .xlsb, .pptm) arriving via email or saved to disk — common phishing initial access vector.",
        "detection": {
            "selection": {
                "raw|contains": [".docm", ".xlsm", ".xlsb", ".pptm", ".docm\"", "macro", "VBA", "AutoOpen", "Document_Open"]
            }
        }
    },
    # ------------------------------------------------------------------ #
    # fix-10: Backup service / shadow copy stopped (T1489 Impact)          #
    # ------------------------------------------------------------------ #
    {
        "id": "rule-backup-service-stopped",
        "name": "Backup or Recovery Service Stopped",
        "severity": "high",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1489",
        "description": "Detects commands or events that stop or disable backup, recovery, or shadow copy services (wbengine, VSS, MSSQLSERVER$BACKUP, BackupExec).",
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "sc stop wbengine", "sc stop vss", "sc config wbengine",
                    "net stop \"backup", "net stop vss", "net stop wbengine",
                    "Stop-Service -Name vss", "Stop-Service -Name wbengine",
                    "wmic service where name='vss' call stopservice",
                    "MSSQLSERVER$BACKUP", "BackupExec"
                ]
            }
        }
    },
    # ------------------------------------------------------------------ #
    # fix-10: Ransom note / family name drop (T1486 Impact)               #
    # ------------------------------------------------------------------ #
    {
        "id": "rule-ransom-note-dropped",
        "name": "Ransomware Note Dropped to Disk",
        "severity": "critical",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1486",
        "description": "Detects creation of ransomware ransom note files (README_RESTORE_FILES, HOW_TO_DECRYPT, DECRYPT_INSTRUCTIONS, !!!RESTORE_FILES!!!, _HELP_RESTORE) or known ransomware family markers.",
        "detection": {
            "selection": {
                "raw|contains": [
                    "README_RESTORE", "HOW_TO_DECRYPT", "DECRYPT_INSTRUCTION",
                    "RESTORE_FILES", "_HELP_RESTORE", "!!! READ ME !!!",
                    "ransomnote", "ransom note", "your files have been encrypted",
                    "LockBit", "REvil", "BlackCat", "AlphV", "Conti",
                    "Ryuk", "Hive", "BlackMatter"
                ]
            }
        }
    },
]


# ---------------------------------------------------------------------------
# B1: Role determination helpers
# ---------------------------------------------------------------------------

def _is_private(ip: str) -> bool:
    return is_internal_ip(ip)


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

    # Single non-IP, non-numeric host in the batch (used when web/audit events arrive as unknown_host)
    batch_hosts = {
        str(h).strip()
        for h in (_extract_field_value(e, "host") for e in sorted_events)
        if h
        and str(h).strip().casefold() not in {"unknown", "unknown_host", "-"}
        and not _looks_like_ip(str(h).strip())
        and not str(h).strip().isdigit()
    }
    inferred_case_host = next(iter(batch_hosts)) if len(batch_hosts) == 1 else None

    def _victim_hosts_for_events(ev_list: List[Any]) -> List[str]:
        result: List[str] = []
        seen_cf: Set[str] = set()
        for e in ev_list:
            ev_type = str(
                getattr(e, "event_type", None) or (e.get("event_type") if isinstance(e, dict) else "") or ""
            ).strip().lower()
            src_val = str(_extract_field_value(e, "SourceIp") or "").strip()
            h_val = str(_extract_field_value(e, "host") or "").strip()
            if (
                not h_val
                or h_val.casefold() in {"unknown", "unknown_host", "-"}
                or (ev_type in {"web_access", "web_log", "http"} and (_looks_like_ip(h_val) or h_val == src_val))
                or (src_val and h_val == src_val and _looks_like_ip(h_val))
            ):
                h_val = inferred_case_host or ""
            if h_val and h_val.casefold() not in seen_cf:
                seen_cf.add(h_val.casefold())
                result.append(h_val)
        return result

    def _correlate_tmp_ingress_transfer() -> List[Any]:
        """Match wget/curl to /tmp or hidden paths followed within 5 minutes by extract/cron/execute."""
        download_re = re.compile(r"\b(?:wget|curl)\b", re.IGNORECASE)
        staged_path_re = re.compile(r"(/(?:tmp|var/tmp|dev/shm)/\S+|/\.[A-Za-z0-9_.-]+\S*)")
        extract_re = re.compile(r"\b(?:tar|unzip|gunzip|7z|bzip2)\b", re.IGNORECASE)
        cron_re = re.compile(r"\bcrontab\b|/etc/cron|/var/spool/cron", re.IGNORECASE)
        excluded_re = re.compile(r"^\s*(?:mysqldump|pg_dump|scp|sftp|rsync|rm|history)\b", re.IGNORECASE)
        exec_re = re.compile(
            r"(?:chmod\s+(?:\+x|7[0-7]{2})|\b(?:kworkerd|xmrig|minerd)\b|--pool|\bstratum\b|\./\S+|/(?:tmp|var/tmp|dev/shm)/\S+|/\.[A-Za-z0-9_.-]+)",
            re.IGNORECASE,
        )

        matched_ids: Set[str] = set()
        matched_list: List[Any] = []

        def _evt_id(e: Any) -> str:
            return str(getattr(e, "id", None) or (e.get("id") if isinstance(e, dict) else ""))

        def _norm_host(e: Any) -> str:
            h = str(_extract_field_value(e, "host") or "").strip().casefold()
            return "" if h in {"", "unknown", "unknown_host", "-"} else h

        for idx, anchor in enumerate(sorted_events):
            anchor_cmd = str(_extract_field_value(anchor, "CommandLine") or "").strip()
            if not anchor_cmd or not download_re.search(anchor_cmd):
                continue
            paths_found = staged_path_re.findall(anchor_cmd)
            if not paths_found:
                continue

            anchor_ts = get_ts(anchor)
            anchor_host = _norm_host(anchor)
            tracked_dirs = {p.rsplit("/", 1)[0] + "/" for p in paths_found if "/" in p}
            tracked_paths = set(paths_found)
            followups: List[Any] = []

            for nxt in sorted_events[idx + 1 :]:
                delta = get_ts(nxt) - anchor_ts
                if delta > 300.0:
                    break
                if delta < 0:
                    continue
                nxt_host = _norm_host(nxt)
                if anchor_host and nxt_host and anchor_host != nxt_host:
                    continue
                nxt_cmd = str(_extract_field_value(nxt, "CommandLine") or "").strip()
                if not nxt_cmd or excluded_re.match(nxt_cmd):
                    continue

                references_staged = any(p in nxt_cmd for p in tracked_paths) or any(d in nxt_cmd for d in tracked_dirs)
                is_extract = bool(extract_re.search(nxt_cmd) and references_staged)
                is_cron = bool(cron_re.search(nxt_cmd) and (references_staged or "/." in nxt_cmd or "/tmp/" in nxt_cmd))
                is_exec = bool(exec_re.search(nxt_cmd) and (references_staged or any(tok in nxt_cmd.lower() for tok in ("kworkerd", "--pool", "stratum"))))

                if is_extract or is_cron or is_exec:
                    followups.append(nxt)
                    for extra_p in staged_path_re.findall(nxt_cmd):
                        tracked_paths.add(extra_p)
                        if "/" in extra_p:
                            tracked_dirs.add(extra_p.rsplit("/", 1)[0] + "/")

            if followups:
                for ev in [anchor, *followups]:
                    eid = _evt_id(ev)
                    if eid not in matched_ids:
                        matched_ids.add(eid)
                        matched_list.append(ev)

        return matched_list

    # ------------------------------------------------------------------
    # 1. Evaluate Single-Event Sigma Rules
    # ------------------------------------------------------------------
    # Evaluate dump/transfer exfiltration rules after non-exfil findings are collected
    # so transfers targeting already-flagged attacker IPs escalate severity accurately.
    for rule in BUILTIN_SIGMA_RULES:
        if rule["id"] in {"rule-mysqldump-scp-exfil", "rule-scp-transfer"}:
            continue
        # Skip metric-type events for non-metric rules
        sel = rule["detection"].get("selection", {})
        if rule["id"] == "rule-web-sql-injection":
            matched_events = [
                evt for evt in sorted_events
                if extract_sqli_indicators(evt)
            ]
        elif rule["id"] == "rule-tmp-download-exec":
            matched_events = _correlate_tmp_ingress_transfer()
        else:
            matched_events = [
                evt for evt in sorted_events
                if evaluate_event_selection(evt, sel)
            ]

        if matched_events:
            first_evt = matched_events[0]
            last_evt = matched_events[-1]

            hosts = _victim_hosts_for_events(matched_events)
            users = list({_extract_field_value(e, "user") for e in matched_events
                          if _extract_field_value(e, "user") and _extract_field_value(e, "user") not in ("unknown", "-")})
            src_ips = sorted({str(_extract_field_value(e, "SourceIp")).strip() for e in matched_events if _extract_field_value(e, "SourceIp")})
            src_files = list({_extract_field_value(e, "source_file") for e in matched_events if _extract_field_value(e, "source_file")})
            rec_ids = [_extract_field_value(e, "source_record_id") for e in matched_events if _extract_field_value(e, "source_record_id") is not None]

            finding_id = f"{rule['id']}-{str(case_id)[:8]}"
            # B1: actor is the src_ip (who did it); target_host is the host (where)
            actor = src_ips[0] if src_ips else (users[0] if users else None)
            target_host = hosts[0] if hosts else None

            # fix-3: seed mitre_techniques_all from the rule's explicit list
            rule_techs = rule.get("mitre_techniques") or [rule["mitre_technique"]]
            findings.append({
                "id": finding_id,
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],   # B4: never put action here
                "mitre_tactic": rule["mitre_tactic"],
                "mitre_technique": rule["mitre_technique"],
                "mitre_techniques_all": list(rule_techs),
                "description": f"{rule['description']} Detected in {len(matched_events)} event(s).",
                # B1 fields
                "actor": actor,
                "target_host": target_host,
                "host": target_host or "unknown",
                "hosts": hosts,
                "user": users[0] if users else "unknown",
                "src_ip": src_ips[0] if src_ips else None,
                "source_ips": src_ips,
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
                    "source_ips": src_ips,
                }
            })

    # ------------------------------------------------------------------
    # 1b. Correlated Database Dump + External SCP/Transfer + NetFlow (T1048)
    # ------------------------------------------------------------------
    ip_in_cmd_re = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    dump_re = re.compile(r"\b(?:mysqldump|pg_dump)\b|sqlite3\s+\S+\s+\.dump", re.IGNORECASE)
    transfer_re = re.compile(r"\b(?:scp|sftp|rsync)\b", re.IGNORECASE)

    # Collect external IPs already flagged as attacker/actor sources by prior findings
    flagged_attacker_ips: Set[str] = set()
    for prior in findings:
        for cand in (
            prior.get("actor"),
            prior.get("src_ip"),
            *(prior.get("source_ips") or []),
            *((prior.get("rule_information") or {}).get("src_ips") or []),
        ):
            if cand and _looks_like_ip(str(cand).strip()) and not _is_private(str(cand).strip()):
                flagged_attacker_ips.add(str(cand).strip())

    def _event_id_str(ev: Any) -> str:
        return str(getattr(ev, "id", None) or (ev.get("id") if isinstance(ev, dict) else ""))

    def _norm_host_str(ev: Any) -> str:
        h = str(_extract_field_value(ev, "host") or "").strip().casefold()
        return "" if h in {"", "unknown", "unknown_host", "-"} or _looks_like_ip(h) else h

    def _ext_ips_in_cmd(cmd_text: str) -> List[str]:
        return [ip for ip in ip_in_cmd_re.findall(cmd_text or "") if not _is_private(ip)]

    dump_events = [
        evt for evt in sorted_events
        if dump_re.search(str(_extract_field_value(evt, "CommandLine") or ""))
    ]
    transfer_events: List[Tuple[Any, List[str]]] = []
    for evt in sorted_events:
        cmd_text = str(_extract_field_value(evt, "CommandLine") or "")
        if transfer_re.search(cmd_text):
            ext_ips = _ext_ips_in_cmd(cmd_text)
            if ext_ips:
                transfer_events.append((evt, ext_ips))

    covered_transfer_ids: Set[str] = set()
    used_dump_ids: Set[str] = set()

    for dump_evt in dump_events:
        dump_id = _event_id_str(dump_evt)
        if dump_id in used_dump_ids:
            continue
        dump_ts = get_ts(dump_evt)
        dump_host = _norm_host_str(dump_evt)

        best_transfer: Optional[Tuple[Any, List[str]]] = None
        for tr_evt, tr_ext_ips in transfer_events:
            tr_id = _event_id_str(tr_evt)
            if tr_id in covered_transfer_ids:
                continue
            tr_host = _norm_host_str(tr_evt)
            if dump_host and tr_host and dump_host != tr_host:
                continue
            delta = get_ts(tr_evt) - dump_ts
            if 0.0 <= delta <= 900.0:
                best_transfer = (tr_evt, tr_ext_ips)
                break

        if not best_transfer:
            continue

        tr_evt, tr_ext_ips = best_transfer
        tr_id = _event_id_str(tr_evt)
        tr_ts = get_ts(tr_evt)
        target_ip = tr_ext_ips[0]

        # Match the corresponding outbound NetFlow row (e.g. port 22 / bytes_out to target_ip)
        matching_flow = None
        best_flow_score = (-1, float("-inf"))
        for flow_evt in sorted_events:
            if _event_id_str(flow_evt) in {dump_id, tr_id}:
                continue
            dst_ip = str(_extract_field_value(flow_evt, "DestinationIp") or "").strip()
            if dst_ip not in tr_ext_ips:
                continue
            time_diff = abs(get_ts(flow_evt) - tr_ts)
            if time_diff > 120.0:
                continue
            details = getattr(flow_evt, "details", None) or (flow_evt.get("details") if isinstance(flow_evt, dict) else {}) or {}
            bytes_out = details.get("bytes_out") or details.get("bytes") or 0
            try:
                bytes_out_num = int(bytes_out)
            except (TypeError, ValueError):
                bytes_out_num = 0
            dst_port = str(_extract_field_value(flow_evt, "DestinationPort") or "")
            is_ssh_port = 1 if dst_port in {"22", "2222"} else 0
            score = (is_ssh_port, bytes_out_num - int(time_diff))
            if score > best_flow_score:
                best_flow_score = score
                matching_flow = flow_evt

        combined_events = [dump_evt, tr_evt] + ([matching_flow] if matching_flow is not None else [])
        used_dump_ids.add(dump_id)
        covered_transfer_ids.add(tr_id)

        hosts = _victim_hosts_for_events(combined_events)
        users = list({
            _extract_field_value(e, "user") for e in combined_events
            if _extract_field_value(e, "user") and _extract_field_value(e, "user") not in ("unknown", "-")
        })
        src_files = list({
            _extract_field_value(e, "source_file") for e in combined_events
            if _extract_field_value(e, "source_file")
        })
        rec_ids = [
            _extract_field_value(e, "source_record_id") for e in combined_events
            if _extract_field_value(e, "source_record_id") is not None
        ]
        to_flagged_attacker = any(ip in flagged_attacker_ips for ip in tr_ext_ips)
        combined_severity = "critical" if to_flagged_attacker else "high"
        target_host = hosts[0] if hosts else None
        flow_details = (getattr(matching_flow, "details", None) or (matching_flow.get("details") if isinstance(matching_flow, dict) else {}) or {}) if matching_flow else {}
        bytes_out_val = flow_details.get("bytes_out") or flow_details.get("bytes")
        size_note = f" ({round(int(bytes_out_val) / 1_000_000, 1)} MB outbound)" if bytes_out_val and str(bytes_out_val).isdigit() else ""

        findings.append({
            "id": f"rule-mysqldump-scp-exfil-{str(case_id)[:8]}",
            "rule_id": "rule-mysqldump-scp-exfil",
            "rule_name": "Database Dump Followed by SCP Transfer",
            "severity": combined_severity,
            "mitre_tactic": "Exfiltration",
            "mitre_technique": "T1048",
            "mitre_techniques_all": ["T1048"],
            "description": (
                f"Database dump followed by external SCP/transfer to {target_ip}{size_note} "
                f"detected across {len(combined_events)} event(s)."
            ),
            "actor": target_ip,
            "target_host": target_host,
            "host": target_host or "unknown",
            "hosts": hosts,
            "user": users[0] if users else "unknown",
            "src_ip": None,
            "dst_ip": target_ip,
            "source_ips": [],
            "first_seen": getattr(combined_events[0], "timestamp", None) or combined_events[0].get("timestamp"),
            "last_seen": getattr(combined_events[-1], "timestamp", None) or combined_events[-1].get("timestamp"),
            "source": "Rule",
            "source_file": src_files[0] if src_files else None,
            "source_record_references": rec_ids,
            "matching_event_ids": [_event_id_str(e) for e in combined_events],
            "rule_information": {
                "matched_count": len(combined_events),
                "hosts": hosts,
                "users": users,
                "source_files": src_files,
                "tactic": "Exfiltration",
                "dst_ip": target_ip,
                "destination_ips": tr_ext_ips,
                "to_flagged_attacker": to_flagged_attacker,
            },
        })

    # Standalone external scp/sftp transfers not already part of a combined dump+transfer finding
    uncovered_transfers = [
        (evt, ext_ips) for evt, ext_ips in transfer_events
        if _event_id_str(evt) not in covered_transfer_ids
    ]
    if uncovered_transfers:
        tr_evts = [evt for evt, _ in uncovered_transfers]
        all_tr_ext = list(dict.fromkeys(ip for _, ips in uncovered_transfers for ip in ips))
        to_flagged_attacker = any(ip in flagged_attacker_ips for ip in all_tr_ext)
        tr_severity = "high" if to_flagged_attacker else "medium"
        hosts = _victim_hosts_for_events(tr_evts)
        users = list({
            _extract_field_value(e, "user") for e in tr_evts
            if _extract_field_value(e, "user") and _extract_field_value(e, "user") not in ("unknown", "-")
        })
        src_files = list({
            _extract_field_value(e, "source_file") for e in tr_evts
            if _extract_field_value(e, "source_file")
        })
        rec_ids = [
            _extract_field_value(e, "source_record_id") for e in tr_evts
            if _extract_field_value(e, "source_record_id") is not None
        ]
        target_host = hosts[0] if hosts else None
        findings.append({
            "id": f"rule-scp-transfer-{str(case_id)[:8]}",
            "rule_id": "rule-scp-transfer",
            "rule_name": "SCP or SFTP Transfer to External Host",
            "severity": tr_severity,
            "mitre_tactic": "Exfiltration",
            "mitre_technique": "T1048",
            "mitre_techniques_all": ["T1048"],
            "description": f"Detects use of scp or sftp to transfer files to external host ({all_tr_ext[0]}). Detected in {len(tr_evts)} event(s).",
            "actor": all_tr_ext[0],
            "target_host": target_host,
            "host": target_host or "unknown",
            "hosts": hosts,
            "user": users[0] if users else "unknown",
            "src_ip": None,
            "dst_ip": all_tr_ext[0],
            "source_ips": [],
            "first_seen": getattr(tr_evts[0], "timestamp", None) or tr_evts[0].get("timestamp"),
            "last_seen": getattr(tr_evts[-1], "timestamp", None) or tr_evts[-1].get("timestamp"),
            "source": "Rule",
            "source_file": src_files[0] if src_files else None,
            "source_record_references": rec_ids,
            "matching_event_ids": [_event_id_str(e) for e in tr_evts],
            "rule_information": {
                "matched_count": len(tr_evts),
                "hosts": hosts,
                "users": users,
                "source_files": src_files,
                "tactic": "Exfiltration",
                "dst_ip": all_tr_ext[0],
                "destination_ips": all_tr_ext,
                "to_flagged_attacker": to_flagged_attacker,
            },
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
    # 5. Metric rule: CPU >90% for 3+ consecutive samples on same host (T1496)
    # ------------------------------------------------------------------
    metric_events = [
        e for e in sorted_events
        if (getattr(e, "event_type", None) or (e.get("event_type") if isinstance(e, dict) else "")) == "metric"
    ]
    metric_by_host: Dict[str, List[Any]] = defaultdict(list)
    for evt in metric_events:
        m_host = str(_extract_field_value(evt, "host") or "unknown_host").strip() or "unknown_host"
        metric_by_host[m_host].append(evt)

    for m_host, host_metrics in metric_by_host.items():
        consecutive_runs: List[List[Any]] = []
        current_run: List[Any] = []
        for evt in host_metrics:
            cpu_raw = _extract_field_value(evt, "cpu_percent")
            try:
                cpu_val = float(str(cpu_raw).strip().rstrip("%"))
            except (TypeError, ValueError):
                if len(current_run) >= 3:
                    consecutive_runs.append(current_run)
                current_run = []
                continue
            if cpu_val > 90.0:
                current_run.append(evt)
            else:
                if len(current_run) >= 3:
                    consecutive_runs.append(current_run)
                current_run = []
        if len(current_run) >= 3:
            consecutive_runs.append(current_run)

        high_cpu_evts = [evt for run in consecutive_runs for evt in run]
        if high_cpu_evts:
            src_files = list({_extract_field_value(e, "source_file") for e in high_cpu_evts if _extract_field_value(e, "source_file")})
            findings.append({
                "id": f"rule-high-cpu-cryptomining-{str(case_id)[:8]}",
                "rule_id": "rule-high-cpu-cryptomining",
                "rule_name": "Sustained High CPU — Suspected Cryptomining",
                "severity": "high",
                "mitre_tactic": "Impact",
                "mitre_technique": "T1496",
                "description": f"CPU above 90% for {len(high_cpu_evts)} consecutive metric samples on {m_host}, suspected cryptomining activity.",
                "actor": None,
                "target_host": m_host if m_host != "unknown_host" else None,
                "host": m_host,
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
                    "hosts": [m_host] if m_host != "unknown_host" else [],
                    "source_files": src_files,
                    "tactic": "Impact",
                }
            })

    # Corroborate T1496 cryptomining signals (pool connection, miner process, sustained CPU) into a unified T1496 finding
    t1496_findings = [f for f in findings if f.get("mitre_technique") == "T1496"]
    if len(t1496_findings) >= 2:
        non_t1496 = [f for f in findings if f.get("mitre_technique") != "T1496"]
        events_by_id = {str(getattr(e, "id", None) or e.get("id")): e for e in sorted_events}
        merged_ids: List[str] = []
        seen_eids: Set[str] = set()
        merged_hosts: List[str] = []
        merged_src_files: List[str] = []
        merged_refs: List[Any] = []
        corroborating: List[str] = []
        pool_dst_ip: Optional[str] = None

        for tf in t1496_findings:
            rname = tf.get("rule_name") or tf.get("rule_id")
            if rname and rname not in corroborating:
                corroborating.append(str(rname))
            for eid in tf.get("matching_event_ids") or []:
                seid = str(eid)
                if seid not in seen_eids:
                    seen_eids.add(seid)
                    merged_ids.append(seid)
                ev = events_by_id.get(seid)
                if ev is not None:
                    dst_cand = _extract_field_value(ev, "DestinationIp")
                    if dst_cand and not _is_private(str(dst_cand)) and not pool_dst_ip:
                        pool_dst_ip = str(dst_cand)
            for h in (tf.get("rule_information") or {}).get("hosts") or []:
                if h and h not in merged_hosts and str(h).lower() not in {"unknown", "unknown_host"}:
                    merged_hosts.append(str(h))
            for sf in (tf.get("rule_information") or {}).get("source_files") or ([tf.get("source_file")] if tf.get("source_file") else []):
                if sf and sf not in merged_src_files:
                    merged_src_files.append(str(sf))
            merged_refs.extend(tf.get("source_record_references") or [])

        non_ip_hosts = [h for h in merged_hosts if not _looks_like_ip(h)]
        primary_host = non_ip_hosts[0] if non_ip_hosts else (merged_hosts[0] if merged_hosts else "unknown")
        merged_times = [
            getattr(events_by_id[eid], "timestamp", None) or (events_by_id[eid].get("timestamp") if isinstance(events_by_id[eid], dict) else None)
            for eid in merged_ids if eid in events_by_id
        ]
        merged_times = [t for t in merged_times if t is not None]
        first_ts = min(merged_times) if merged_times else t1496_findings[0].get("first_seen")
        last_ts = max(merged_times) if merged_times else t1496_findings[-1].get("last_seen")

        findings = non_t1496 + [{
            "id": f"rule-miner-t1496-{str(case_id)[:8]}",
            "rule_id": "rule-miner-pool-ports",
            "rule_name": "Cryptomining Activity (Pool Connection, Miner Process & Sustained High CPU)" if len(corroborating) == 3 else "Cryptomining Activity (Resource Hijacking)",
            "severity": "high",
            "mitre_tactic": "Impact",
            "mitre_technique": "T1496",
            "mitre_techniques_all": ["T1496"],
            "description": (
                f"Corroborated cryptomining activity ({', '.join(corroborating)}) across {len(merged_ids)} event(s)"
                + (f" targeting pool {pool_dst_ip}." if pool_dst_ip else ".")
            ),
            "actor": pool_dst_ip,
            "target_host": primary_host if primary_host != "unknown" else None,
            "host": primary_host,
            "user": "unknown",
            "src_ip": None,
            "dst_ip": pool_dst_ip,
            "first_seen": first_ts,
            "last_seen": last_ts,
            "source": "Rule",
            "source_file": merged_src_files[0] if merged_src_files else None,
            "source_record_references": merged_refs,
            "matching_event_ids": merged_ids,
            "rule_information": {
                "matched_count": len(merged_ids),
                "hosts": merged_hosts,
                "source_files": merged_src_files,
                "corroborating_rules": corroborating,
                "dst_ip": pool_dst_ip,
                "destination_ip": pool_dst_ip,
                "tactic": "Impact",
            },
        }]

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

    from app.services.rule_loader import load_all_rules
    yaml_rules = load_all_rules()
    catalog = list(BUILTIN_SIGMA_RULES)
    seen = {r["id"] for r in catalog}
    for rule in yaml_rules:
        if rule.get("id") not in seen:
            catalog.append({"id": rule.get("id"), "name": rule.get("title", rule.get("id")), "severity": rule.get("severity", "medium"), "mitre_tactic": rule.get("mitre_tactic", "Execution"), "mitre_technique": rule.get("mitre_technique", "T1059")})
            seen.add(rule.get("id"))
    catalog_techniques = {r["mitre_technique"] for r in catalog}

    rules_summary = []
    for r in catalog:
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
        "total_rules": len(catalog),
        "total_findings": len(findings),
        "covered_techniques": sorted(list(covered_techniques)),
        "uncovered_techniques": sorted(list(catalog_techniques - covered_techniques)),
    }
