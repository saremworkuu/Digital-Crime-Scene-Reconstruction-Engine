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
from app.parsers.vuln_scan import VulnScanParser
from app.parsers.windows_evtx import WindowsEVTXParser
from app.schemas.events import EventResponse
from app.services.correlation import correlate_attack_chains
from app.services.normalizer import normalize_records


WEB_COMPROMISE_DIR = (
    Path(__file__).resolve().parents[1] / "test_evidence" / "web_server_compromise"
)


def test_vuln_scan_parser_dispatch_fields_severities_and_correlation_exclusion(tmp_path):
    vuln_path = WEB_COMPROMISE_DIR / "06_vulnerability_scan_2026-07-15.xml"
    assert vuln_path.is_file()

    # Registry picks VulnScanParser only for VulnScan XML, keeping WindowsEVTXParser for other XML
    assert isinstance(get_parser(vuln_path), VulnScanParser)
    evtx_xml = tmp_path / "sysmon.xml"
    evtx_xml.write_text(
        '<Events><Event><System><EventID>1</EventID><TimeCreated SystemTime="2026-07-22T01:00:00Z"/>'
        '<Computer>WEB-01</Computer></System></Event></Events>',
        encoding="utf-8",
    )
    assert isinstance(get_parser(evtx_xml), WindowsEVTXParser)

    records = VulnScanParser().parse(vuln_path, original_filename="06_vulnerability_scan_2026-07-15.xml")
    assert len(records) == 4
    normalized = normalize_records(records, default_filename="06_vulnerability_scan_2026-07-15.xml")
    assert len(normalized) == 4

    responses = [
        EventResponse.model_validate({
            "id": uuid.uuid4(),
            "case_id": uuid.uuid4(),
            "evidence_id": uuid.uuid4(),
            "timestamp": rec["timestamp"],
            "event_type": rec["event_type"],
            "source": rec["source"],
            "details": rec["details"],
        })
        for rec in normalized
    ]

    assert [(r.event_id, r.severity, r.status, r.ticket, r.first_detected, r.date_only, r.category, r.is_attack_path) for r in responses] == [
        ("F-101", "high", "open", "SEC-4411", "2026-07-15", True, "context", False),
        ("F-102", "high", "open", "SEC-4412", "2026-07-15", True, "context", False),
        ("F-103", "medium", "open", "SEC-4413", "2026-07-15", True, "context", False),
        ("F-104", "low", "closed", "SEC-4399", "2026-06-01", True, "context", False),
    ]

    # Context events must never appear in attack correlation chains
    incident_evt = {
        "id": str(uuid.uuid4()),
        "timestamp": "2026-07-22T01:25:07Z",
        "event_type": "web_access",
        "host": "WEB-01",
        "severity": "high",
        "action": "SQLi",
        "is_attack_path": True,
        "details": {"host": "WEB-01"},
    }
    chains = correlate_attack_chains([r.model_dump() for r in responses] + [incident_evt])
    chained_ids = {ev["id"] for c in chains for ev in c.get("events", [])}
    for r in responses:
        assert str(r.id) not in chained_ids


def test_vuln_scan_upload_via_api_preserves_severities_and_context_fields(tmp_path, monkeypatch):
    vuln_path = WEB_COMPROMISE_DIR / "06_vulnerability_scan_2026-07-15.xml"
    assert vuln_path.is_file()

    test_db = tmp_path / "vuln_scan.sqlite"
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
        name="VulnScan Case",
        description="XML scan",
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
        with vuln_path.open("rb") as fh:
            res = client.post(
                f"/api/v1/evidence/cases/{case.id}/evidence/upload",
                files={"file": ("06_vulnerability_scan_2026-07-15.xml", fh, "application/xml")},
                data={"description": "vuln scan"},
            )
            assert res.status_code == 201, res.text
        assert res.json()["parser_used"] == "VulnScanParser"
        assert res.json()["event_count"] == 4

        events = client.get(f"/api/v1/events/cases/{case.id}/events").json()
        assert len(events) == 4
        by_id = {e["event_id"]: e for e in events}
        assert by_id["F-101"]["severity"] == "high"
        assert by_id["F-102"]["severity"] == "high"
        assert by_id["F-103"]["severity"] == "medium"
        assert by_id["F-104"]["severity"] == "low"
        assert by_id["F-104"]["status"] == "closed"
        assert by_id["F-104"]["first_detected"] == "2026-06-01"
        assert all(e["category"] == "context" and e["date_only"] is True and e["is_attack_path"] is False for e in events)
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
