import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

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
from app.services.detection import detect_web_scanner_recon
from app.services.rule_loader import load_all_rules


WEB_COMPROMISE_DIR = (
    Path(__file__).resolve().parents[1] / "test_evidence" / "web_server_compromise"
)


def test_web_scanner_recon_rule_loaded_and_detects_404_burst_and_scanner_ua():
    loaded_ids = {r["id"] for r in load_all_rules()}
    assert "web_scanner_recon" in loaded_ids

    base_ts = datetime(2026, 7, 22, 1, 12, 0, tzinfo=timezone.utc)
    # 10+ 404s within 60 seconds without a scanner user agent
    burst_events = [
        SimpleNamespace(
            id=f"404-{i}",
            timestamp=base_ts + timedelta(seconds=i * 4),
            event_type="web_access",
            details={
                "host": "WEB-01",
                "source_ip": "198.51.100.55",
                "status_code": 404,
                "user_agent": "Mozilla/5.0",
            },
        )
        for i in range(10)
    ]
    # Benign customer with a couple of 404s and normal 200 traffic must not trigger
    benign_events = [
        SimpleNamespace(
            id="ok-1",
            timestamp=base_ts + timedelta(seconds=1),
            event_type="web_access",
            details={"host": "WEB-01", "source_ip": "192.0.2.28", "status_code": 200, "user_agent": "Mozilla/5.0"},
        ),
        SimpleNamespace(
            id="ok-2",
            timestamp=base_ts + timedelta(seconds=5),
            event_type="web_access",
            details={"host": "WEB-01", "source_ip": "192.0.2.28", "status_code": 404, "user_agent": "Mozilla/5.0"},
        ),
    ]

    findings = detect_web_scanner_recon(burst_events + benign_events)
    assert len(findings) == 1
    assert findings[0]["mitre_technique"] == "T1595"
    assert findings[0]["mitre_tactic"] == "Reconnaissance"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["source_ips"] == ["198.51.100.55"]
    assert "192.0.2.28" not in findings[0]["source_ips"]


def test_web_scanner_recon_sample_case_covers_nikto_and_excludes_benign_customers(tmp_path, monkeypatch):
    apache_path = WEB_COMPROMISE_DIR / "01_apache_access.log"
    auth_path = WEB_COMPROMISE_DIR / "02_auth.log"
    assert apache_path.is_file() and auth_path.is_file()

    test_db = tmp_path / "scanner_recon.sqlite"
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
        name="Scanner Recon Case",
        description="Apache + auth logs",
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
        for fname in ("01_apache_access.log", "02_auth.log"):
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
        recon_findings = [
            d for d in detections
            if str(d.get("mitre_technique") or "").startswith("T1595")
            or d.get("mitre_tactic") == "Reconnaissance"
        ]
        assert len(recon_findings) == 1, f"Expected one scanner/recon finding, got {recon_findings}"

        recon = recon_findings[0]
        assert recon["severity"] == "medium"
        assert recon["mitre_tactic"] == "Reconnaissance"
        assert "WEB-01" in (recon.get("hosts") or [])
        assert recon.get("source_ips") == ["203.0.113.140"]

        matched_events = [events_by_id[eid] for eid in recon["matched_event_ids"]]
        nikto_events = [
            e for e in matched_events
            if "nikto" in str((e.get("details") or {}).get("user_agent") or "").lower()
            or "nikto" in str(e.get("raw") or "").lower()
        ]
        assert len(nikto_events) == 40
        assert not any("192.0.2." in str(e.get("src_ip") or "") for e in matched_events)
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
