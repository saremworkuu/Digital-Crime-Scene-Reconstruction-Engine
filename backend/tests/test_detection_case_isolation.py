import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.api.v1 import detections as detection_api
from app.db.base import Base
from app.db.models.case import Case
from app.db.models.detection import Detection, DetectionSeverity
from app.db.models.detection_event import DetectionEvent
from app.db.models.evidence import Evidence
from app.db.models.events import Event
from app.services.report_fixes import dedupe_detections


def _memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)(), engine


def test_recomputing_case_a_never_reads_or_changes_case_b_rows():
    db, engine = _memory_db()
    case_a, case_b = uuid.uuid4(), uuid.uuid4()
    actor = uuid.uuid4()
    evidence_a, evidence_b = uuid.uuid4(), uuid.uuid4()
    event_a, event_b = uuid.uuid4(), uuid.uuid4()
    old_a, stable_b = uuid.uuid4(), uuid.uuid4()
    db.add_all([
        Case(id=case_a, name="A", created_by=actor), Case(id=case_b, name="B", created_by=actor),
        Evidence(id=evidence_a, case_id=case_a, uploaded_by=actor, filename="a.log", file_type="text/plain", file_path="a.log", sha256_hash="a" * 64, file_size=1),
        Evidence(id=evidence_b, case_id=case_b, uploaded_by=actor, filename="b.log", file_type="text/plain", file_path="b.log", sha256_hash="b" * 64, file_size=1),
        Event(id=event_a, case_id=case_a, evidence_id=evidence_a, timestamp=datetime(2026, 9, 3, tzinfo=timezone.utc), event_type="process", source="test", details={"host": "HOST-A"}, fingerprint="a" * 64),
        Event(id=event_b, case_id=case_b, evidence_id=evidence_b, timestamp=datetime(2026, 9, 3, tzinfo=timezone.utc), event_type="process", source="test", details={"host": "HOST-B"}, fingerprint="b" * 64),
        Detection(id=old_a, case_id=case_a, rule_id="old-a", rule_name="Old A", severity=DetectionSeverity.HIGH, description="old", rule_information={}),
        Detection(id=stable_b, case_id=case_b, rule_id="stable-b", rule_name="B finding", severity=DetectionSeverity.HIGH, description="must remain", rule_information={"matching_event_ids": [str(event_b)]}),
        DetectionEvent(detection_id=old_a, event_id=event_b),
        DetectionEvent(detection_id=stable_b, event_id=event_b),
    ])
    db.commit()
    statements = []

    def capture_sql(_conn, _cursor, statement, parameters, _context, _many):
        if " from events" in statement.lower() or " from detections" in statement.lower() or " from detection_events" in statement.lower():
            statements.append((statement.lower(), parameters))

    from sqlalchemy import event as sqlalchemy_event
    sqlalchemy_event.listen(engine, "before_cursor_execute", capture_sql)
    finding = {
        "rule_id": "case-isolation-test", "rule_name": "Case Isolation Activity", "severity": "high",
        "mitre_technique": "T1059", "mitre_tactic": "Execution", "description": "linked event pair",
        "matching_event_ids": [str(event_a), str(event_b)],
    }
    with patch.object(detection_api, "execute_detections_on_events", return_value=[finding]):
        rebuilt = detection_api._execute_case_detections(case_a, db)

    current_b = db.get(Detection, stable_b)
    assert current_b is not None and current_b.description == "must remain"
    assert db.execute(select(DetectionEvent.event_id).where(DetectionEvent.detection_id == stable_b)).scalars().all() == [event_b]
    case_a_links = db.execute(select(DetectionEvent.event_id).where(DetectionEvent.detection_id == rebuilt[0].id)).scalars().all()
    assert case_a_links == [event_a]
    event_selects = [sql for sql, _ in statements if " from events" in sql and sql.lstrip().startswith("select")]
    assert event_selects and all("events.case_id" in sql for sql in event_selects)
    assert all("where detections.case_id" in sql for sql, _ in statements if " from detections" in sql and sql.lstrip().startswith("select"))
    db.close()
    engine.dispose()


def test_finding_merge_scope_keeps_each_observed_host_for_key_behaviors():
    hosts = ["SRV-FS-02", "SRV-BKP-01", "WS-ACC-03"]
    event_rows = []
    findings = []
    for behavior, title, technique in (
        ("remote", "Remote Service Creation (PsExec)", "T1569.002"),
        ("shadow", "Shadow Copy Deletion", "T1490"),
        ("encryptor", "Mass File Rename With Unknown Extension", "T1486"),
    ):
        for index, host in enumerate(hosts):
            event_id = f"{behavior}-{index}"
            event_rows.append(SimpleNamespace(
                id=event_id, timestamp=datetime(2026, 9, 3, 9, index, tzinfo=timezone.utc),
                event_type="edr_alert", details={"host": host},
            ))
            findings.append({
                "rule_id": behavior, "rule_name": title, "severity": "high", "mitre_technique": technique,
                "mitre_tactic": "Impact" if behavior != "remote" else "Lateral Movement",
                "description": f"{title} on {host}", "host": host,
                "matching_event_ids": [event_id], "rule_information": {"host": host},
            })

    merged = detection_api._coalesce_findings_by_host(findings, event_rows)
    for behavior in ("remote", "shadow", "encryptor"):
        rows = [row for row in merged if row["rule_id"] == behavior]
        assert len(rows) == len(hosts)
        assert {row["host"] for row in rows} == set(hosts)
        assert all(len(row["matching_event_ids"]) == 1 for row in rows)


def test_report_deduplication_uses_host_as_part_of_merge_key():
    findings = [
        {"id": "fs", "rule_name": "Shadow Copy Deletion", "matching_event_ids": ["e1"], "mitre_technique": "T1490", "severity": "high"},
        {"id": "bkp", "rule_name": "Inhibit System Recovery via Shadow Copy Deletion", "matching_event_ids": ["e2"], "mitre_technique": "T1490", "severity": "high"},
    ]
    result = dedupe_detections(findings, event_hosts={"e1": "SRV-FS-02", "e2": "SRV-BKP-01"})
    assert len(result) == 2
