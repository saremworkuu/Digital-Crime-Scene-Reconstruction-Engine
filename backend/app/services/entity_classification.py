"""Shared, evidence-led entity classification helpers."""
import ipaddress
import os
from typing import Any


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


def infrastructure_role(*, tactic: str = "", field_role: str = "") -> str | None:
    """Map explicit finding context to a display role; no traffic-only claims."""
    role = (field_role or "").strip().lower()
    if role in {"c2", "command_and_control", "command and control"} or tactic == "Command and Control":
        return "C2"
    if role in {"payload", "payload_source"}:
        return "Payload"
    if tactic == "Initial Access":
        return "Payload"
    if role in {"exfiltration", "exfil", "exfiltration_destination"} or tactic == "Exfiltration":
        return "Exfiltration"
    if role in {"attack_source", "source", "attacker"}:
        return "Attack Source"
    if tactic in {"Credential Access", "Reconnaissance"}:
        return "Attack Source"
    return None
