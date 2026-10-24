"""MITRE ATT&CK catalog helpers — resolve known IDs or mint custom ones."""

from __future__ import annotations

import re
import uuid

from sqlalchemy.orm import Session

from app.models.models import TechniqueHit

# Common enterprise techniques used in IR workflows
MITRE_CATALOG: dict[str, tuple[str, str]] = {
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1059.003": ("Windows Command Shell", "Execution"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
    "T1078.002": ("Domain Accounts", "Defense Evasion"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.001": ("Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("SMB/Windows Admin Shares", "Lateral Movement"),
    "T1566": ("Phishing", "Initial Access"),
    "T1566.001": ("Spearphishing Attachment", "Initial Access"),
    "T1566.002": ("Spearphishing Link", "Initial Access"),
    "T1204": ("User Execution", "Execution"),
    "T1204.002": ("Malicious File", "Execution"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1003.001": ("LSASS Memory", "Credential Access"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1071.001": ("Web Protocols", "Command and Control"),
    "T1218": ("System Binary Proxy Execution", "Defense Evasion"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1547": ("Boot or Logon Autostart Execution", "Persistence"),
    "T1053": ("Scheduled Task/Job", "Persistence"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1018": ("Remote System Discovery", "Discovery"),
    "T1489": ("Service Stop", "Impact"),
}

MITRE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
CUSTOM_ID_RE = re.compile(r"^CUSTOM-\d{3,}$", re.IGNORECASE)


def normalize_mitre_id(value: str) -> str:
    return (value or "").strip().upper()


def lookup_mitre(mitre_id: str) -> tuple[str, str] | None:
    key = normalize_mitre_id(mitre_id)
    return MITRE_CATALOG.get(key)


def _next_custom_id(db: Session, case_id: uuid.UUID) -> str:
    existing = (
        db.query(TechniqueHit.mitre_id)
        .filter(TechniqueHit.case_id == case_id, TechniqueHit.mitre_id.like("CUSTOM-%"))
        .all()
    )
    max_n = 0
    for (mid,) in existing:
        try:
            max_n = max(max_n, int(str(mid).rsplit("-", 1)[-1]))
        except ValueError:
            continue
    return f"CUSTOM-{max_n + 1:03d}"


def resolve_technique(
    db: Session,
    case_id: uuid.UUID,
    mitre_id: str,
    name: str = "",
    tactic: str = "",
) -> tuple[str, str, str]:
    """
    Resolve technique fields:
    - Known ATT&CK ID → fill name/tactic from catalog when blank
    - Blank / unknown / invalid ID → mint CUSTOM-NNN and keep analyst name/tactic
    """
    raw = normalize_mitre_id(mitre_id)
    name = (name or "").strip()
    tactic = (tactic or "").strip()

    if raw and lookup_mitre(raw):
        catalog_name, catalog_tactic = MITRE_CATALOG[raw]
        return raw, name or catalog_name, tactic or catalog_tactic

    # Official-looking ID that isn't in our catalog — keep if format is valid
    if raw and MITRE_ID_RE.match(raw):
        return raw, name or f"Technique {raw}", tactic or "Unknown"

    # Missing or non-standard → assign our custom MITRE-style ID
    custom = _next_custom_id(db, case_id)
    return custom, name or "Custom technique (analyst-defined)", tactic or "Unknown"
