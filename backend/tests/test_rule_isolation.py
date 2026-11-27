import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.main import app as fastapi_app
from app.core.dependencies import get_current_user
from app.core.security import hash_password
from app.db.base import Base
import app.db.models  # noqa: F401
from app.db.models.audit_log import AuditLog
from app.db.models.case import Case, CaseStatus
from app.db.models.events import Event
from app.db.models.evidence import Evidence, ParsingStatus
from app.db.models.user import User, UserRole
from app.db.session import get_db
from app.parsers.registry import get_parser
from app.services import detection_engine as detection_engine_module
from app.services.detection_engine import execute_detections_on_events
from app.services.normalizer import normalize_records


WEB_COMPROMISE_DIR = (
    Path(__file__).resolve().parents[1] / "test_evidence" / "web_server_compromise"
)


def test_normal_input_findings_unchanged_and_no_rule_errors():
    events = []
    for fname in (
        "01_apache_access.log",
        "02_auth.log",
        "03_auditd.log",
        "04_waf_alerts.json",
        "05_mysql_general.log",
        "07_netflow_export.csv",
        "08_system_metrics.csv",
    ):
        fpath = WEB_COMPROMISE_DIR / fname
        assert fpath.is_file(), f"Missing fixture: {fpath}"
        records = get_parser(fpath, original_filename=fname).parse(fpath, original_filename=fname)
        for rec in normalize_records(records, default_filename=fname):
            rec["id"] = str(uuid.uuid4())
            events.append(rec)

    rule_errors = []
    findings = execute_detections_on_events(events, uuid.uuid4(), rule_errors=rule_errors)
    assert rule_errors == []
    by_rule = {f["rule_id"]: f for f in findings}
    assert {
        "rule-web-sql-injection",
        "rule-double-extension-upload",
        "rule-webshell-request",
        "rule-reverse-shell-pattern",
        "rule-miner-pool-ports",
    }.issubset(by_rule)
    assert by_rule["rule-web-sql-injection"]["severity"] == "high"
    assert len(by_rule["rule-web-sql-injection"]["matching_event_ids"]) > 0


def test_failing_sqli_rule_does_not_abort_later_rules_and_records_error(tmp_path, caplog):
    sample_events = [
        {
            "id": "evt-webshell",
            "timestamp": "2026-08-01T10:00:00Z",
            "event_type": "web_access",
            "details": {"host": "WEB-01", "src_ip": "203.0.113.10", "raw": "GET /shell.php?cmd=id HTTP/1.1"},
        },
        {
            "id": "evt-miner",
            "timestamp": "2026-08-01T10:01:00Z",
            "event_type": "network_connection",
            "details": {"host": "WEB-01", "dst_port": 3333},
        },
    ]

    rule_errors = []
    with caplog.at_level(logging.WARNING):
        with patch.object(detection_engine_module, "extract_sqli_indicators", side_effect=RuntimeError("simulated_sqli_crash")):
            findings = execute_detections_on_events(sample_events, uuid.uuid4(), rule_errors=rule_errors)

    rule_ids = {f["rule_id"] for f in findings}
    assert "rule-webshell-request" in rule_ids
    assert "rule-miner-pool-ports" in rule_ids
    assert rule_errors == [{"rule_id": "rule-web-sql-injection", "error": "simulated_sqli_crash"}]
    assert any("rule-web-sql-injection" in rec.message for rec in caplog.records)

    # Also verify end-to-end API behavior on POST /run, GET /coverage, and GET /detections/rules
    test_db = tmp_path / "rule_isolation.sqlite"
    engine = create_engine(f"sqlite:///{test_db}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    db = TestSession()
    user = User(
        username=f"inv_{uuid.uuid4().hex[:8]}",
        email=f"inv_{uuid.uuid4().hex[:8]}@dcsre.test",
        hashed_password=hash_password("Investigator#2026"),
        role=UserRole.INVESTIGATOR,
        is_active=True,
    )
    db.add(user)
    db.flush()
    case = Case(name="Rule Isolation Case", description="", status=CaseStatus.OPEN, created_by=user.id)
    db.add(case)
    db.flush()
    ev_id = uuid.uuid4()
    db.add(
        Evidence(
            id=ev_id, case_id=case.id, uploaded_by=user.id,
            filename="web.log", description="", file_type="text/plain",
            file_path=str(tmp_path / "web.log"), sha256_hash="a" * 64,
            file_size=10, parsing_status=ParsingStatus.PARSED,
        )
    )
    db.add_all([
        Event(
            id=uuid.uuid4(), case_id=case.id, evidence_id=ev_id,
            timestamp=datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc),
            event_type="web_access", source="web",
            details=sample_events[0]["details"], fingerprint="1" * 64,
        ),
        Event(
            id=uuid.uuid4(), case_id=case.id, evidence_id=ev_id,
            timestamp=datetime(2026, 8, 1, 10, 1, 0, tzinfo=timezone.utc),
            event_type="network_connection", source="netflow",
            details=sample_events[1]["details"], fingerprint="2" * 64,
        ),
    ])
    db.commit()

    def override_get_db():
        session = TestSession()
        try:
            yield session
        finally:
            session.close()

    prev_db = fastapi_app.dependency_overrides.get(get_db)
    prev_user = fastapi_app.dependency_overrides.get(get_current_user)
    fastapi_app.dependency_overrides[get_db] = override_get_db
    fastapi_app.dependency_overrides[get_current_user] = lambda: user
    try:
        client = TestClient(fastapi_app)
        with patch.object(detection_engine_module, "extract_sqli_indicators", side_effect=RuntimeError("simulated_sqli_crash")):
            run_res = client.post(f"/api/v1/detections/cases/{case.id}/run")
            assert run_res.status_code == 200, run_res.text
            run_body = run_res.json()
            assert {"rule-webshell-request", "rule-miner-pool-ports"} <= {d["rule_id"] for d in run_body}
            assert run_body[0]["rule_errors"] == [
                {"rule_id": "rule-web-sql-injection", "error": "simulated_sqli_crash"}
            ]

            cov_res = client.get(f"/api/v1/detections/cases/{case.id}/coverage")
            assert cov_res.status_code == 200, cov_res.text
            assert cov_res.json()["rule_errors"] == [
                {"rule_id": "rule-web-sql-injection", "error": "simulated_sqli_crash"}
            ]

        rules_res = client.get("/api/v1/detections/rules")
        assert rules_res.status_code == 200
        sqli_rule = next(r for r in rules_res.json() if r["id"] == "rule-web-sql-injection")
        assert sqli_rule["evaluation_note"] and "extract_sqli_indicators" in sqli_rule["evaluation_note"]
        assert "raw|contains" in (sqli_rule["yaml_content"] or "")

        check_db = TestSession()
        try:
            err_audit = check_db.execute(
                select(AuditLog).where(
                    AuditLog.case_id == case.id,
                    AuditLog.action == "detection.rule_errors",
                )
            ).scalar_one_or_none()
            assert err_audit is not None
            assert err_audit.details["rule_errors"] == [
                {"rule_id": "rule-web-sql-injection", "error": "simulated_sqli_crash"}
            ]
        finally:
            check_db.close()
    finally:
        if prev_db is not None:
            fastapi_app.dependency_overrides[get_db] = prev_db
        else:
            fastapi_app.dependency_overrides.pop(get_db, None)
        if prev_user is not None:
            fastapi_app.dependency_overrides[get_current_user] = prev_user
        else:
            fastapi_app.dependency_overrides.pop(get_current_user, None)
        db.close()
        engine.dispose()
