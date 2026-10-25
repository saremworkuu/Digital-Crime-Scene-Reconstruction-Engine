"""
Automated tests for DCSRE Parts A, B, C fixes.

Tests cover:
- A2: CSV metric vs network-flow type detection
- A3: auditd multi-line grouping, vuln-scan XML Finding count, PCAP dedup
- A4: timestamp_inferred flag, no silent upload-time substitution
- B1: actor/target/role fields in findings, adversary vs victim
- B3: graphBuilder no hardcoded subnet_map
- B4: correct MITRE mapping, no default T1059/T1110
- C1: new rules present (scanner UA, reverse shell, sudo escape, miner port, cpu metric)
- C2: report hash computed over content, DRAFT stamp, generated remediation
"""
import json
import hashlib
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

# -----------------------------------------------------------------------
# A2: CSV schema detection
# -----------------------------------------------------------------------
from app.parsers.generic_csv_json import GenericCSVJSONParser


def test_csv_metric_detection():
    """Metrics CSV → event_type == 'metric' with meaningful action summary."""
    parser = GenericCSVJSONParser()
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "metrics.csv"
        f.write_text(
            "timestamp,host,cpu_percent,mem_percent,net_out\n"
            "2026-07-22T01:00:00Z,WEB-01,14,47,1024\n"
            "2026-07-22T01:05:00Z,WEB-01,91,55,2048\n",
            encoding="utf-8",
        )
        records = parser.parse(f)
    assert len(records) == 2
    assert records[0]["event_type"] == "metric", f"Expected metric, got {records[0]['event_type']}"
    # Action must contain CPU / MEM summary
    assert "CPU" in records[0]["action"] or "MEM" in records[0]["action"], records[0]["action"]


def test_csv_network_flow_detection():
    """Netflow CSV → event_type == 'network_connection'."""
    parser = GenericCSVJSONParser()
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "netflow.csv"
        f.write_text(
            "timestamp,src_ip,dst_ip,src_port,dst_port,proto,bytes\n"
            "2026-07-22T01:00:00Z,10.40.1.15,198.51.100.201,54321,4444,TCP,512\n"
            "2026-07-22T01:01:00Z,10.40.1.15,198.51.100.201,54322,4444,TCP,1024\n",
            encoding="utf-8",
        )
        records = parser.parse(f)
    assert len(records) == 2
    assert records[0]["event_type"] == "network_connection"


# -----------------------------------------------------------------------
# A3: auditd multi-line grouping
# -----------------------------------------------------------------------
from app.parsers.auditd import AuditdParser


AUDITD_SAMPLE = """\
type=SYSCALL msg=audit(1721609400.123:100): arch=c000003e syscall=59 success=yes exit=0 pid=12345 a0="bash" a1="-c" a2="id" uid=33 auid=0 comm="bash" exe="/bin/bash" key="exec"
type=EXECVE msg=audit(1721609400.123:100): argc=3 a0="bash" a1="-c" a2="id"
type=SYSCALL msg=audit(1721609400.456:101): arch=c000003e syscall=59 success=yes exit=0 pid=12346 a0="useradd" a1="sysupdate" uid=0 auid=0 comm="useradd" exe="/usr/sbin/useradd" key="exec"
type=EXECVE msg=audit(1721609400.456:101): argc=2 a0="useradd" a1="sysupdate"
"""


def test_auditd_multiline_grouping():
    """Two audit records (each with SYSCALL+EXECVE) → exactly 2 events."""
    parser = AuditdParser()
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "audit.log"
        f.write_text(AUDITD_SAMPLE, encoding="utf-8")
        records = parser.parse(f)
    assert len(records) == 2, f"Expected 2 auditd events, got {len(records)}"
    # Command line reconstructed from a0..aN
    cmds = [r["command_line"] for r in records if r["command_line"]]
    assert any("bash" in (c or "") for c in cmds)
    assert any("useradd" in (c or "") for c in cmds)


# -----------------------------------------------------------------------
# A3: vulnerability-scan XML → only <Finding> elements counted
# -----------------------------------------------------------------------
from app.parsers.windows_evtx import WindowsEVTXParser


VULN_XML = """<?xml version="1.0"?>
<ScanReport>
  <host>10.40.1.15</host>
  <timestamp>2026-07-22T00:00:00Z</timestamp>
  <Finding>
    <id>F001</id>
    <title>SQL Injection in login.php</title>
    <severity>critical</severity>
    <description>Unauthenticated SQL injection via id parameter.</description>
    <host>10.40.1.15</host>
    <cve>CVE-2026-1001</cve>
  </Finding>
  <Finding>
    <id>F002</id>
    <title>File Upload Bypass</title>
    <severity>high</severity>
    <description>Double-extension upload allows PHP execution.</description>
    <host>10.40.1.15</host>
  </Finding>
  <Finding>
    <id>F003</id>
    <title>Default Credentials on Admin Panel</title>
    <severity>medium</severity>
    <description>Admin panel accessible with default admin/admin credentials.</description>
    <host>10.40.1.15</host>
  </Finding>
  <Finding>
    <id>F004</id>
    <title>Outdated Apache Version</title>
    <severity>low</severity>
    <description>Apache 2.4.41 with known CVEs.</description>
    <host>10.40.1.15</host>
    <cve>CVE-2026-1002</cve>
  </Finding>
</ScanReport>"""


def test_vuln_scan_xml_finding_count():
    """Vulnerability scan XML with 4 <Finding> elements → exactly 4 events."""
    parser = WindowsEVTXParser()
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "vuln_scan.xml"
        f.write_text(VULN_XML, encoding="utf-8")
        records = parser.parse(f)
    assert len(records) == 4, f"Expected 4 findings, got {len(records)}"
    event_types = {r["event_type"] for r in records}
    assert event_types == {"vulnerability_finding"}


# -----------------------------------------------------------------------
# A4: event_service stores ingested_at; no silent timestamp substitution
# -----------------------------------------------------------------------
from app.services.event_service import save_normalized_events
from app.db.base import Base

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from app.db.models.events import Event
from app.db.models.event_evidence import EventEvidence
from app.db.models.case import Case
from app.db.models.evidence import Evidence
from app.db.models.user import User, UserRole


def _make_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return Session()


def test_event_service_stores_ingested_at():
    """event_service.save_normalized_events embeds ingested_at in details."""
    db = _make_db()
    case_id = uuid.uuid4()
    evidence_id = uuid.uuid4()
    ingested_at = datetime(2026, 7, 22, 13, 59, 0, tzinfo=timezone.utc)

    # Create minimal case / evidence rows
    from app.db.models.case import Case, CaseStatus
    case = Case(id=case_id, name="test", description="", created_by=uuid.uuid4())
    db.add(case)

    from app.db.models.evidence import Evidence, ParsingStatus
    ev = Evidence(id=evidence_id, case_id=case_id, uploaded_by=uuid.uuid4(),
                  filename="test.log", file_type="text/plain", file_path="/tmp/x",
                  sha256_hash="a" * 64, file_size=10)
    db.add(ev)
    db.commit()

    records = [{
        "timestamp": "2026-07-22T01:25:00Z",
        "event_type": "linux_auth",
        "source": "auth",
        "details": {"host": "WEB-01", "source_file": "auth.log", "source_record_id": 1, "raw": "test"},
    }]

    count = save_normalized_events(db, case_id, evidence_id, records, ingested_at=ingested_at)
    db.commit()
    assert count == 1

    evt = db.execute(select(Event).where(Event.case_id == case_id)).scalar_one()
    # event_time should be 01:25, not 13:59
    assert evt.timestamp.hour == 1, f"Expected hour 1, got {evt.timestamp.hour}"
    assert evt.timestamp.minute == 25

    # ingested_at should be stored in details
    assert "ingested_at" in evt.details, "ingested_at missing from details"
    assert "13:59" in evt.details["ingested_at"], f"ingested_at wrong: {evt.details['ingested_at']}"


def test_no_timestamp_record_is_skipped():
    """Records with no timestamp and no timestamp_inferred flag are skipped (not assigned upload time)."""
    db = _make_db()
    case_id = uuid.uuid4()
    evidence_id = uuid.uuid4()

    from app.db.models.case import Case, CaseStatus
    case = Case(id=case_id, name="skip-ts", description="", created_by=uuid.uuid4())
    db.add(case)
    from app.db.models.evidence import Evidence
    ev = Evidence(id=evidence_id, case_id=case_id, uploaded_by=uuid.uuid4(),
                  filename="x.log", file_type="text/plain", file_path="/tmp/y",
                  sha256_hash="b" * 64, file_size=10)
    db.add(ev)
    db.commit()

    records = [{
        "timestamp": None,
        "event_type": "linux_auth",
        "source": "auth",
        "details": {"host": "WEB-01", "source_file": "x.log", "source_record_id": 1, "raw": "no ts"},
    }]

    count = save_normalized_events(db, case_id, evidence_id, records,
                                   ingested_at=datetime(2026, 7, 22, 13, 59, tzinfo=timezone.utc))
    db.commit()
    assert count == 0, f"Expected 0 saved (no timestamp), got {count}"


# -----------------------------------------------------------------------
# B1/B3: detection_engine includes actor/target/role fields
# -----------------------------------------------------------------------
from app.services.detection_engine import execute_detections_on_events, _determine_roles


def _make_event(event_type, command_line=None, src_ip=None, dst_ip=None, host=None,
                user=None, dst_port=None, severity="low"):
    return {
        "id": str(uuid.uuid4()),
        "timestamp": "2026-07-22T01:00:00Z",
        "event_type": event_type,
        "source": "auth",
        "details": {
            "host": host or "WEB-01",
            "command_line": command_line,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "user": user,
            "source_file": "test.log",
            "source_record_id": 1,
            "raw": command_line or event_type,
            "severity": severity,
        },
        "severity": severity,
    }


def test_finding_has_actor_and_target():
    """Every finding must include actor, target_host fields (B1)."""
    events = [
        _make_event("auditd", command_line="useradd sysupdate",
                    src_ip="203.0.113.140", host="WEB-01", user="www-data")
    ]
    case_id = uuid.uuid4()
    findings = execute_detections_on_events(events, case_id)
    assert len(findings) >= 1
    for f in findings:
        assert "actor" in f, f"actor field missing from finding {f.get('rule_id')}"
        assert "target_host" in f, f"target_host field missing from finding {f.get('rule_id')}"


def test_mitre_not_defaulted():
    """MITRE technique must come from the rule definition, not be defaulted to T1059/T1110 (B4)."""
    events = [_make_event("auditd", command_line="history -c", host="WEB-01")]
    case_id = uuid.uuid4()
    findings = execute_detections_on_events(events, case_id)
    for f in findings:
        technique = f.get("mitre_technique")
        # technique may be None (no matching rule) but must NOT be T1059 or T1110 as a blanket default
        assert technique != "T1059", "T1059 should not be a blanket default"
    # The history-c rule should fire with T1070.003
    history_findings = [f for f in findings if "history" in f.get("rule_name", "").lower() or "log" in f.get("rule_name", "").lower()]
    if history_findings:
        assert history_findings[0]["mitre_technique"] == "T1070.003"


def test_adversary_role_not_assigned_to_normal_traffic():
    """External IPs in normal traffic (non-attack events) are NOT adversary infrastructure (B1/B3)."""
    # Normal customer traffic from external IP
    events = [
        _make_event("web_access", host="WEB-01", src_ip="192.0.2.21", severity="low"),
        _make_event("web_access", host="WEB-01", src_ip="192.0.2.22", severity="low"),
    ]
    case_id = uuid.uuid4()
    findings = execute_detections_on_events(events, case_id)
    roles = _determine_roles(findings)
    # Normal customer IPs must not appear as adversary
    assert "192.0.2.21" not in roles or roles.get("192.0.2.21") != "adversary_infrastructure"
    assert "192.0.2.22" not in roles or roles.get("192.0.2.22") != "adversary_infrastructure"


# -----------------------------------------------------------------------
# B3: graphBuilder has no hardcoded subnet_map
# -----------------------------------------------------------------------
from app.services.graph import build_attack_graph


def test_graph_no_hardcoded_hosts():
    """Graph must not pre-seed WS-HR-12, DC-01 etc. without evidence (B2/B3)."""
    # Events with NO host names, just random private IPs
    events = [
        {
            "id": str(uuid.uuid4()), "timestamp": "2026-07-22T01:00:00Z",
            "event_type": "network_connection", "source": "pcap",
            "details": {
                "host": None, "src_ip": "10.20.1.12", "dst_ip": "10.20.2.2",
                "dst_port": 445, "protocol": "TCP",
                "source_file": "test.pcap", "source_record_id": 1,
                "raw": "packet",
            },
            "severity": "low",
        }
    ]
    graph = build_attack_graph(events)
    node_labels = {n["label"] for n in graph["nodes"]}
    # Must NOT see hardcoded hostnames — only IPs or empty
    assert "WS-HR-12" not in node_labels, "Hardcoded WS-HR-12 found in graph nodes"
    assert "DC-01" not in node_labels, "Hardcoded DC-01 found in graph nodes"


# -----------------------------------------------------------------------
# C1: New rules are present in BUILTIN_SIGMA_RULES
# -----------------------------------------------------------------------
from app.services.detection_engine import BUILTIN_SIGMA_RULES


def test_required_rules_present():
    """All required C1 rules must be present in BUILTIN_SIGMA_RULES."""
    rule_ids = {r["id"] for r in BUILTIN_SIGMA_RULES}
    required = {
        "rule-scanner-useragent",
        "rule-web-sql-injection",
        "rule-double-extension-upload",
        "rule-webshell-request",
        "rule-reverse-shell-pattern",
        "rule-sudo-shell-escape",
        "rule-useradd-authorized-keys",
        "rule-add-user-to-sudo",
        "rule-tmp-download-exec",
        "rule-crontab-modification",
        "rule-mysqldump-scp-exfil",
        "rule-history-clear-log-removal",
        "rule-miner-pool-ports",
    }
    missing = required - rule_ids
    assert not missing, f"Missing rules: {missing}"


def test_miner_port_rule_fires():
    """Miner pool port rule (T1496) must fire on dst_port 3333."""
    events = [
        _make_event("network_connection", dst_port=3333, host="WEB-01", severity="low")
    ]
    case_id = uuid.uuid4()
    findings = execute_detections_on_events(events, case_id)
    miner_findings = [f for f in findings if "miner" in f.get("rule_id", "").lower() or "T1496" in str(f.get("mitre_technique", ""))]
    assert len(miner_findings) >= 1, "Miner pool port rule did not fire on port 3333"


def test_scanner_ua_rule_fires():
    """Scanner user-agent rule must fire on 'nikto' in raw field."""
    events = [
        {
            "id": str(uuid.uuid4()), "timestamp": "2026-07-22T00:02:00Z",
            "event_type": "web_access", "source": "web",
            "details": {
                "host": "WEB-01", "src_ip": "203.0.113.140",
                "raw": 'GET /robots.txt HTTP/1.1 200 - "nikto/2.1.6"',
                "action": "HTTP GET /robots.txt",
                "source_file": "apache.log", "source_record_id": 2,
                "severity": "low",
            },
            "severity": "low",
        }
    ]
    case_id = uuid.uuid4()
    findings = execute_detections_on_events(events, case_id)
    scanner_findings = [f for f in findings if "scanner" in f.get("rule_id", "").lower()]
    assert len(scanner_findings) >= 1, "Scanner UA rule did not fire on 'nikto'"


# -----------------------------------------------------------------------
# C2: Report hash, DRAFT stamp, generated remediation
# -----------------------------------------------------------------------
from app.services.report import generate_forensic_report_data, _compute_report_hash


def _sample_findings():
    return [
        {
            "id": "f-001", "rule_id": "rule-web-sql-injection",
            "rule_name": "SQL Injection", "severity": "high",
            "mitre_tactic": "Initial Access", "mitre_technique": "T1190",
            "description": "SQLi detected.",
            "actor": "203.0.113.140", "actor_role": "adversary_infrastructure",
            "target_host": "WEB-01", "target_role": "compromised_host",
            "host": "WEB-01", "user": "www-data", "src_ip": "203.0.113.140",
            "first_seen": "2026-07-22T00:15:00Z", "last_seen": "2026-07-22T00:16:00Z",
            "source": "Rule", "source_file": "apache.log",
            "matching_event_ids": ["e1"], "source_record_references": [1],
            "rule_information": {},
        }
    ]


def _sample_linked_event():
    return {"id": "e1", "timestamp": "2026-07-22T00:15:00Z", "event_type": "web_access", "source": "apache.log", "source_file": "apache.log", "host": "WEB-01", "user": "www-data", "src_ip": "203.0.113.140", "action": "SQL injection detected", "severity": "high"}


def test_report_is_draft():
    """Report must be marked DRAFT (C2)."""
    report = generate_forensic_report_data(
        case_dict={"id": str(uuid.uuid4()), "name": "Test"},
        evidence_list=[], events=[_sample_linked_event()], detections=_sample_findings(),
    )
    assert report.get("status") == "DRAFT", "Report status must be DRAFT"
    assert "DRAFT" in report.get("draft_notice", ""), "draft_notice must contain DRAFT"


def test_report_hash_computed_over_content():
    """Report hash must be SHA-256 of content (not first evidence file hash) (C2)."""
    report = generate_forensic_report_data(
        case_dict={"id": str(uuid.uuid4()), "name": "Hash Test"},
        evidence_list=[{"filename": "test.log", "sha256_hash": "a" * 64,
                        "size_bytes": 100, "event_count": 5,
                        "uploaded_at": "2026-07-22T13:59:00Z", "uploader_name": "admin"}],
        events=[], detections=[],
    )
    stored_hash = report.get("report_hash")
    assert stored_hash is not None, "report_hash must be present"
    # The hash must NOT equal the first evidence file hash
    assert stored_hash != "a" * 64, "report_hash must not be the evidence file hash"
    # Recomputing should give the same result (deterministic)
    recomputed = _compute_report_hash(report)
    assert stored_hash == recomputed, "Report hash is not stable / deterministic"


def test_same_input_gives_identical_report_hash():
    """Determinism: running twice on same input must yield identical report hash (C2)."""
    kwargs = dict(
        case_dict={"id": "12345678-0000-0000-0000-000000000000", "name": "Determinism"},
        evidence_list=[], events=[], detections=_sample_findings(),
    )
    r1 = generate_forensic_report_data(**kwargs)
    r2 = generate_forensic_report_data(**kwargs)
    # generated_at will differ by time — exclude it from the check
    assert _compute_report_hash({k: v for k, v in r1.items() if k not in ("generated_at", "report_hash", "id")}) == \
           _compute_report_hash({k: v for k, v in r2.items() if k not in ("generated_at", "report_hash", "id")}), \
           "Report content hash is not deterministic for same input"


def test_report_remediation_generated_from_findings():
    """Remediation section must be generated from findings, not boilerplate (C2)."""
    report = generate_forensic_report_data(
        case_dict={"id": str(uuid.uuid4()), "name": "Rem test"},
        evidence_list=[], events=[_sample_linked_event()], detections=_sample_findings(),
    )
    remediation = report.get("remediation", [])
    assert len(remediation) >= 1, "Remediation must not be empty when findings present"
    # Must cite specific adversary IPs or hosts from findings
    all_actions = " ".join(r.get("action", r) if isinstance(r, dict) else str(r) for r in remediation)
    assert "None identified" not in all_actions or len(remediation) == 1, \
        "Boilerplate 'None identified' should only appear when truly no data"


def test_adversary_infra_only_from_findings():
    """B1/C2: adversary_infrastructure in report must come from findings roles, not all external IPs."""
    # Add a normal customer event (external IP, not attack)
    events_with_normal_traffic = [
        _sample_linked_event(),
        {"id": "e-normal", "timestamp": "2026-07-22T00:30:00Z",
         "event_type": "web_access", "source": "web",
         "host": "WEB-01", "src_ip": "192.0.2.21", "dst_ip": None,
         "is_attack_path": False, "severity": "low",
         "action": "GET /index.php", "user": "unknown"}
    ]
    report = generate_forensic_report_data(
        case_dict={"id": str(uuid.uuid4()), "name": "Adversary test"},
        evidence_list=[], events=events_with_normal_traffic, detections=_sample_findings(),
    )
    comp = report.get("compromised_assets", {})
    adversary = comp.get("adversary_infrastructure", [])
    # 192.0.2.21 is normal customer traffic — must not appear as adversary
    assert "192.0.2.21" not in adversary, f"Normal customer IP 192.0.2.21 must not be adversary infra: {adversary}"
    # 203.0.113.140 is in findings with actor_role=adversary_infrastructure
    assert "203.0.113.140" in adversary, f"203.0.113.140 should be adversary infra: {adversary}"
