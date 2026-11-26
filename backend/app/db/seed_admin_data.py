import logging
from datetime import datetime, timezone
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models.contact_message import ContactMessage
from app.db.models.sigma_rule import SigmaRule
from app.db.models.system_settings import SystemSettings

logger = logging.getLogger(__name__)

BASELINE_SIGMA_RULES = [
    {
        "id": "sig-01",
        "name": "LSASS Memory Dump via Taskmgr or ProcDump",
        "severity": "critical",
        "mitre_id": "T1003.001",
        "enabled": True,
        "times_triggered": 0,
        "description": "Detects processes targeting lsass.exe for credential harvesting and in-memory ticket extraction.",
        "query": 'process_name in ("procdump.exe", "procdump64.exe", "taskmgr.exe") and target_process = "lsass.exe"',
        "created_at": datetime(2026, 1, 20, 0, 0, tzinfo=timezone.utc),
    },
    {
        "id": "sig-02",
        "name": "Suspicious PowerShell Base64 Encoded Command Execution",
        "severity": "high",
        "mitre_id": "T1059.001",
        "enabled": True,
        "times_triggered": 0,
        "description": "Identifies PowerShell command lines utilizing encoded commands (-e, -enc, -encodedcommand) to evade inspection.",
        "query": 'process_name = "powershell.exe" and command_line regex "(-e|-enc|-encodedcommand)\\s+[A-Za-z0-9+/=]{20,}"',
        "created_at": datetime(2026, 2, 10, 0, 0, tzinfo=timezone.utc),
    },
]

BASELINE_INBOX_MESSAGES = [
    {
        "id": "msg-01",
        "reference": "አሻራ-748921",
        "sender_name": "SOC Triage Desk",
        "sender_email": "soc-triage@dcsre.org",
        "sender_phone": "+1 (555) 210-4410",
        "subject": "Urgent Chain-of-Custody Verification Request",
        "category": "Incident Report",
        "status": "new",
        "priority": "high",
        "assignee": None,
        "date": datetime(2026, 11, 24, 14, 30, tzinfo=timezone.utc),
        "is_read": False,
        "body": "Requesting SHA-256 verification and timeline export confirmation for the recently uploaded web server intrusion artifacts.",
        "reply_thread": [],
    },
    {
        "id": "msg-02",
        "reference": "አሻራ-748922",
        "sender_name": "DFIR Compliance Lead",
        "sender_email": "compliance@dcsre.org",
        "sender_phone": "+1 (555) 210-8820",
        "subject": "Archive Ingestion & Hash Audit Follow-up",
        "category": "Chain of Custody",
        "status": "in_review",
        "priority": "medium",
        "assignee": None,
        "date": datetime(2026, 11, 25, 9, 15, tzinfo=timezone.utc),
        "is_read": True,
        "body": "Please confirm audit trail retention settings match policy and review the signed custody manifest prior to court disclosure.",
        "reply_thread": [],
    },
]


def seed_admin_data(db: Session):
    """Ensure baseline SystemSettings plus 2 Inbox messages and 2 Detection Rules exist when empty."""
    settings = db.query(SystemSettings).filter(SystemSettings.id == "default").first()
    if not settings:
        settings = SystemSettings(
            id="default",
            time_zone="UTC",
            org_name="አሻራ Cyber Forensic Command",
            retention_days=90,
            min_password_length=12,
            two_factor_enforced=False,
            failed_login_lockout_limit=5,
        )
        db.add(settings)
        logger.info("Initialized default SystemSettings configuration.")

    rule_count = db.query(func.count(SigmaRule.id)).scalar() or 0
    if rule_count == 0:
        for r in BASELINE_SIGMA_RULES:
            db.add(SigmaRule(**r))
        logger.info("Seeded %d baseline Sigma rules.", len(BASELINE_SIGMA_RULES))

    msg_count = db.query(func.count(ContactMessage.id)).scalar() or 0
    if msg_count == 0:
        for m in BASELINE_INBOX_MESSAGES:
            db.add(ContactMessage(**m))
        logger.info("Seeded %d baseline Inbox messages.", len(BASELINE_INBOX_MESSAGES))

    db.commit()
