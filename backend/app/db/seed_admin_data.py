import logging
import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from app.db.models.user import User, UserRole
from app.db.models.case import Case, CaseStatus
from app.db.models.evidence import Evidence, ParsingStatus
from app.db.models.audit_log import AuditLog
from app.db.models.sigma_rule import SigmaRule
from app.db.models.contact_message import ContactMessage
from app.db.models.system_settings import SystemSettings
from app.core.security import hash_password

logger = logging.getLogger(__name__)

SEED_USERS = [
    {
        "id": "222c593addec4265b39e1fa7b82eca1e",
        "username": "saremworkuu",
        "email": "saremworkuu@gmail.com",
        "role": UserRole.ADMIN,
        "department": "Digital Forensic Incident Response (DFIR) Command",
        "status": "active",
        "two_factor_enabled": True,
        "password": "Admin@2026!",
        "sessions": [
            {"id": "sess-01", "device": "Chrome 122 on macOS (Arm64)", "ip": "192.168.1.104", "last_active": "Just now"},
            {"id": "sess-02", "device": "Forensic Lab Workstation 01", "ip": "10.0.4.15", "last_active": "2 hours ago"}
        ]
    },
    {
        "id": "333c593addec4265b39e1fa7b82eca1f",
        "username": "m.vance",
        "email": "m.vance@dcsre.net",
        "role": UserRole.INVESTIGATOR,
        "department": "Cyber Threat Intelligence & Reverse Engineering",
        "status": "active",
        "two_factor_enabled": True,
        "password": "Investigator@2026!",
        "sessions": [
            {"id": "sess-03", "device": "Firefox Developer Edition on Linux", "ip": "10.0.4.22", "last_active": "Yesterday"}
        ]
    },
    {
        "id": "444c593addec4265b39e1fa7b82eca20",
        "username": "e.rostova",
        "email": "e.rostova@dcsre.net",
        "role": UserRole.INVESTIGATOR,
        "department": "Memory Forensics & Network Packet Inspection",
        "status": "active",
        "two_factor_enabled": False,
        "password": "Investigator@2026!",
        "sessions": [
            {"id": "sess-04", "device": "Chrome on Windows 11 Enterprise", "ip": "10.0.4.38", "last_active": "3 hours ago"}
        ]
    },
    {
        "id": "555c593addec4265b39e1fa7b82eca21",
        "username": "d.kim",
        "email": "d.kim@dcsre.audit",
        "role": UserRole.INVESTIGATOR,
        "department": "Forensic Oversight & Compliance Assurance",
        "status": "active",
        "two_factor_enabled": True,
        "password": "Auditor@2026!",
        "sessions": [
            {"id": "sess-05", "device": "Safari on macOS Sequoia", "ip": "172.16.0.5", "last_active": "2 days ago"}
        ]
    }
]

SEED_SIGMA_RULES = [
    {
        "id": "sig-01",
        "name": "LSASS Memory Dump via Taskmgr or ProcDump",
        "severity": "critical",
        "mitre_id": "T1003.001",
        "enabled": True,
        "times_triggered": 14,
        "description": "Detects processes targeting lsass.exe for credential harvesting and in-memory ticket extraction.",
        "query": 'process_name in ("procdump.exe", "procdump64.exe", "taskmgr.exe") and target_process = "lsass.exe"',
        "created_at": datetime.fromisoformat("2026-01-20T00:00:00+00:00")
    },
    {
        "id": "sig-02",
        "name": "Suspicious PowerShell Base64 Encoded Command Execution",
        "severity": "high",
        "mitre_id": "T1059.001",
        "enabled": True,
        "times_triggered": 28,
        "description": "Identifies PowerShell command lines utilizing encoded commands (-e, -enc, -encodedcommand) to evade inspection.",
        "query": 'process_name = "powershell.exe" and command_line regex "(-e|-enc|-encodedcommand)\\s+[A-Za-z0-9+/=]{20,}"',
        "created_at": datetime.fromisoformat("2026-02-10T00:00:00+00:00")
    },
    {
        "id": "sig-03",
        "name": "Ransomware Shadow Copy Deletion via Vssadmin",
        "severity": "critical",
        "mitre_id": "T1490",
        "enabled": True,
        "times_triggered": 4,
        "description": "Flags destructive backup elimination commands executed prior to file encryption.",
        "query": 'process_name = "vssadmin.exe" and command_line contains "delete shadows" and command_line contains "/all"',
        "created_at": datetime.fromisoformat("2026-02-18T00:00:00+00:00")
    },
    {
        "id": "sig-04",
        "name": "Lateral Movement via Pass-The-Hash or WMI Exec",
        "severity": "high",
        "mitre_id": "T1047",
        "enabled": True,
        "times_triggered": 9,
        "description": "Monitors inbound WMI execution creating remote processes on internal targets.",
        "query": 'parent_process = "wmiprvse.exe" and process_name in ("cmd.exe", "powershell.exe", "rundll32.exe")',
        "created_at": datetime.fromisoformat("2026-03-02T00:00:00+00:00")
    },
    {
        "id": "sig-05",
        "name": "Active Directory Reconnaissance using AdFind or BloodHound",
        "severity": "medium",
        "mitre_id": "T1087.002",
        "enabled": True,
        "times_triggered": 42,
        "description": "Discovers LDAP queries enumerating domain trusts, admin accounts, and Kerberos SPNs.",
        "query": 'process_name in ("adfind.exe", "sharpad.exe") or command_line contains "objectcategory=person"',
        "created_at": datetime.fromisoformat("2026-03-15T00:00:00+00:00")
    },
    {
        "id": "sig-06",
        "name": "DNS Tunneling or Data Exfiltration via TXT Queries",
        "severity": "high",
        "mitre_id": "T1048.003",
        "enabled": False,
        "times_triggered": 0,
        "description": "Detects high frequency of unusually long DNS TXT query payloads sent to non-standard nameservers.",
        "query": 'protocol = "DNS" and query_type = "TXT" and query_length > 180 and request_rate > 25_per_minute',
        "created_at": datetime.fromisoformat("2026-04-01T00:00:00+00:00")
    }
]

SEED_MESSAGES = [
    {
        "id": "msg-01",
        "reference": "አሻራ-748921",
        "sender_name": "Marcus Sterling",
        "sender_email": "m.sterling@techcorp.io",
        "sender_phone": "+1 (555) 392-1084",
        "subject": "Urgent: Ransomware IOC Verification Request",
        "category": "Incident Report",
        "status": "new",
        "priority": "high",
        "assignee": None,
        "date": datetime.fromisoformat("2026-10-23T05:30:00+00:00"),
        "is_read": False,
        "body": "We detected DarkLock binary artifacts across two backup controllers at 04:15 UTC. We need urgent validation whether the SHA-256 hashes match your current intelligence database.",
        "reply_thread": []
    },
    {
        "id": "msg-02",
        "reference": "አሻራ-632194",
        "sender_name": "Dr. Aris Thorne",
        "sender_email": "thorne@biohealth-labs.org",
        "sender_phone": "+1 (555) 802-9112",
        "subject": "Suspected Domain Controller Compromise & Data Exfiltration",
        "category": "Incident Report",
        "status": "new",
        "priority": "critical",
        "assignee": "Sarem Worku",
        "date": datetime.fromisoformat("2026-10-23T04:12:00+00:00"),
        "is_read": False,
        "body": "Our EDR flagged mass Kerberoasting and credential dumping. We have isolated DC02 and request an emergency investigation docket under DCSRE protocol.",
        "reply_thread": []
    },
    {
        "id": "msg-03",
        "reference": "አሻራ-519823",
        "sender_name": "Sarah Jenkins",
        "sender_email": "sjenkins@defenselegal.com",
        "sender_phone": "+1 (555) 441-2900",
        "subject": "Inquiry about Forensic Chain of Custody Standards (Court Admissibility)",
        "category": "Chain of Custody",
        "status": "in_review",
        "priority": "medium",
        "assignee": "David Kim",
        "date": datetime.fromisoformat("2026-10-22T18:20:00+00:00"),
        "is_read": True,
        "body": "Could you provide the audit documentation proving the SHA-256 ledger complies with Federal Rule of Evidence 902(14) for self-authenticating digital records?",
        "reply_thread": [
            {
                "id": "rep-01",
                "author": "David Kim (Auditor)",
                "role": "Auditor",
                "message": "Reviewing statutory compliance documentation. Our cryptographic hashes utilize RFC-6962 transparency logs.",
                "timestamp": "2026-10-22T20:10:00Z"
            }
        ]
    },
    {
        "id": "msg-04",
        "reference": "አሻራ-401928",
        "sender_name": "Kofi Mensah",
        "sender_email": "kmensah@cloudguard.systems",
        "sender_phone": "+44 20 7946 0912",
        "subject": "API Access for Enterprise SIEM Integration (Splunk & Sentinel)",
        "category": "General Inquiry",
        "status": "replied",
        "priority": "low",
        "assignee": "Sarem Worku",
        "date": datetime.fromisoformat("2026-10-22T14:05:00+00:00"),
        "is_read": True,
        "body": "Does your platform support automated ingestion webhooks to forward reconstructed 3D attack paths directly into our central SIEM instance?",
        "reply_thread": [
            {
                "id": "rep-02",
                "author": "Sarem Worku (Admin)",
                "role": "Administrator",
                "message": "Yes, DCSRE supports webhook dispatch and STIX/TAXII 2.1 feeds. Documentation has been shared.",
                "timestamp": "2026-10-22T15:30:00Z"
            }
        ]
    },
    {
        "id": "msg-05",
        "reference": "አሻራ-382910",
        "sender_name": "Rachel Adams",
        "sender_email": "rachel.a@finsec-audit.gov",
        "sender_phone": "+1 (555) 710-3329",
        "subject": "Tamper-Evident Ledger Verification Question",
        "category": "Telemetry Query",
        "status": "new",
        "priority": "medium",
        "assignee": None,
        "date": datetime.fromisoformat("2026-10-22T11:45:00+00:00"),
        "is_read": False,
        "body": "We are conducting an annual audit on financial telemetry. Please explain the cryptographic mechanism used to ensure audit records cannot be retroactively altered by administrators.",
        "reply_thread": []
    },
    {
        "id": "msg-06",
        "reference": "አሻራ-291048",
        "sender_name": "PromoteFast Marketing",
        "sender_email": "contact@boost-searches-quick.biz",
        "sender_phone": "+1 (800) 555-0199",
        "subject": "Rank #1 on Google with our SEO Backlink Package",
        "category": "Support",
        "status": "spam",
        "priority": "low",
        "assignee": None,
        "date": datetime.fromisoformat("2026-10-21T09:12:00+00:00"),
        "is_read": True,
        "body": "Hello Webmaster, We noticed your website could use 5,000 monthly backlinks to increase search visibility for digital forensics terms. Special discount today!",
        "reply_thread": []
    },
    {
        "id": "msg-07",
        "reference": "አሻራ-184920",
        "sender_name": "Tariq Al-Mansoor",
        "sender_email": "tariq.ops@cyberhub.ae",
        "sender_phone": "+971 4 312 8844",
        "subject": "Host Hop Telemetry Missing in EVTX Ingestion",
        "category": "Telemetry Query",
        "status": "in_review",
        "priority": "high",
        "assignee": "Marcus Vance",
        "date": datetime.fromisoformat("2026-10-21T07:40:00+00:00"),
        "is_read": True,
        "body": "During ingestion of Windows Event ID 4624 (Logon Type 10 / RDP), certain workstation source IPs are not auto-mapping into the 3D correlation graph.",
        "reply_thread": [
            {
                "id": "rep-03",
                "author": "Marcus Vance",
                "role": "Investigator",
                "message": "Examining parsing logic for IPv6 mapped source addresses in Windows Server 2022.",
                "timestamp": "2026-10-21T10:15:00Z"
            }
        ]
    },
    {
        "id": "msg-08",
        "reference": "አሻራ-109283",
        "sender_name": "Elena Rostova",
        "sender_email": "e.rostova@dcsre.net",
        "sender_phone": "+1 (555) 919-4821",
        "subject": "Requesting Case Reopen for Ticket #2026-CS (New Evidence Surfaced)",
        "category": "Incident Report",
        "status": "replied",
        "priority": "medium",
        "assignee": "Sarem Worku",
        "date": datetime.fromisoformat("2026-10-20T16:00:00+00:00"),
        "is_read": True,
        "body": "A secondary external firewall dump from the branch office contains correlated C2 beacons matching Cobalt Shadow timeline. Requesting status update to Open.",
        "reply_thread": [
            {
                "id": "rep-04",
                "author": "Sarem Worku (Admin)",
                "role": "Administrator",
                "message": "Approved and reopened. Case status transitioned to Open and assigned to Marcus & Elena.",
                "timestamp": "2026-10-20T17:30:00Z"
            }
        ]
    }
]

def seed_admin_data(db: Session):
    # 1. Seed or Update Users
    for u in SEED_USERS:
        existing = db.query(User).filter(User.email == u["email"]).first()
        if not existing:
            new_u = User(
                id=uuid.UUID(u["id"]),
                username=u["username"],
                email=u["email"],
                hashed_password=hash_password(u["password"]),
                role=u["role"],
                is_active=(u["status"] == "active"),
                department=u.get("department"),
                two_factor_enabled=u.get("two_factor_enabled", False),
                status=u.get("status", "active"),
                sessions=u.get("sessions", [])
            )
            db.add(new_u)
            logger.info(f"Seeded user: {u['email']}")
        else:
            if not getattr(existing, "department", None):
                existing.department = u.get("department")
            if not getattr(existing, "status", None):
                existing.status = u.get("status", "active")
            if not getattr(existing, "sessions", None):
                existing.sessions = u.get("sessions", [])
            existing.two_factor_enabled = u.get("two_factor_enabled", False)

    # 2. Seed System Settings
    settings = db.query(SystemSettings).filter(SystemSettings.id == "default").first()
    if not settings:
        settings = SystemSettings(
            id="default",
            time_zone="UTC",
            org_name="አሻራ Cyber Forensic Command",
            retention_days=90,
            min_password_length=12,
            two_factor_enforced=False,
            failed_login_lockout_limit=5
        )
        db.add(settings)
        logger.info("Seeded default SystemSettings.")

    # 3. Seed Sigma Rules
    rule_count = db.query(func.count(SigmaRule.id)).scalar() or 0
    if rule_count == 0:
        for r in SEED_SIGMA_RULES:
            db.add(SigmaRule(
                id=r["id"],
                name=r["name"],
                severity=r["severity"],
                mitre_id=r["mitre_id"],
                enabled=r["enabled"],
                times_triggered=r["times_triggered"],
                description=r["description"],
                query=r["query"],
                created_at=r["created_at"]
            ))
        logger.info(f"Seeded {len(SEED_SIGMA_RULES)} Sigma Rules.")

    # 4. Seed Contact Messages
    msg_count = db.query(func.count(ContactMessage.id)).scalar() or 0
    if msg_count == 0:
        for m in SEED_MESSAGES:
            db.add(ContactMessage(
                id=m["id"],
                reference=m["reference"],
                sender_name=m["sender_name"],
                sender_email=m["sender_email"],
                sender_phone=m["sender_phone"],
                subject=m["subject"],
                category=m["category"],
                status=m["status"],
                priority=m["priority"],
                assignee=m["assignee"],
                date=m["date"],
                is_read=m["is_read"],
                body=m["body"],
                reply_thread=m["reply_thread"]
            ))
        logger.info(f"Seeded {len(SEED_MESSAGES)} Contact Messages.")

    db.commit()
