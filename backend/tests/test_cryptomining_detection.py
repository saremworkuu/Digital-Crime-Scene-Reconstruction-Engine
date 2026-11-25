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
from app.services.detection_engine import execute_detections_on_events


WEB_COMPROMISE_DIR = (
    Path(__file__).resolve().parents[1] / "test_evidence" / "web_server_compromise"
)


def test_cpu_rule_requires_three_consecutive_samples_over_90_same_host():
    def _metric(idx: int, host: str, cpu_pct: float):
        return {
            "id": f"m-{idx}",
            "timestamp": f"2026-07-22T02:{idx * 5:02d}:00Z",
            "event_type": "metric",
            "source": "csv",
            "details": {"host": host, "cpu_pct": cpu_pct, "source_file": "metrics.csv", "source_record_id": idx + 1},
        }

    # Non-consecutive spikes (2 -> drop -> 2) must not fire
    non_consec = [
        _metric(0, "WEB-01", 95),
        _metric(1, "WEB-01", 96),
        _metric(2, "WEB-01", 85),
        _metric(3, "WEB-01", 97),
        _metric(4, "WEB-01", 98),
    ]
    assert [f for f in execute_detections_on_events(non_consec, uuid.uuid4()) if f.get("mitre_technique") == "T1496"] == []

    # Exactly 90.0 is not > 90
    boundary = [_metric(0, "WEB-01", 90), _metric(1, "WEB-01", 95), _metric(2, "WEB-01", 96)]
    assert [f for f in execute_detections_on_events(boundary, uuid.uuid4()) if f.get("mitre_technique") == "T1496"] == []

    # Split across different hosts (2 on WEB-01, 2 on WEB-02) must not fire
    split_hosts = [_metric(0, "WEB-01", 95), _metric(1, "WEB-02", 96), _metric(2, "WEB-01", 97), _metric(3, "WEB-02", 98)]
    assert [f for f in execute_detections_on_events(split_hosts, uuid.uuid4()) if f.get("mitre_technique") == "T1496"] == []

    # 3 consecutive > 90 on same host with cpu_pct column fires T1496
    consec = [_metric(0, "WEB-01", 92), _metric(1, "WEB-01", 95), _metric(2, "WEB-01", 99)]
    findings = [f for f in execute_detections_on_events(consec, uuid.uuid4()) if f.get("mitre_technique") == "T1496"]
    assert len(findings) == 1
    assert findings[0]["matching_event_ids"] == ["m-0", "m-1", "m-2"]


def test_t1496_cryptomining_includes_pool_process_cpu_and_excludes_4444(tmp_path, monkeypatch):
    files_to_upload = [
        ("03_auditd.log", "text/plain"),
        ("07_netflow_export.csv", "text/csv"),
        ("08_system_metrics.csv", "text/csv"),
        ("09_capture_web_attack.pcap", "application/vnd.tcpdump.pcap"),
    ]
    for fname, _ in files_to_upload:
        assert (WEB_COMPROMISE_DIR / fname).is_file(), f"Missing fixture: {fname}"

    test_db = tmp_path / "t1496_test.sqlite"
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
        name="Web Server Compromise T1496 Case",
        description="Verifies T1496 excludes port 4444 and links pool 3333, kworkerd, and CPU > 90%",
        status=CaseStatus.OPEN,
        created_by=user.id,
    )
    db.add(case)
    db.commit()
    case_id = str(case.id)

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
        for fname, mime in files_to_upload:
            with (WEB_COMPROMISE_DIR / fname).open("rb") as fh:
                res = client.post(
                    f"/api/v1/evidence/cases/{case_id}/evidence/upload",
                    files={"file": (fname, fh, mime)},
                    data={"description": fname},
                )
            assert res.status_code == 201, f"{fname}: {res.text}"

        events = client.get(f"/api/v1/events/cases/{case_id}/events").json()
        events_by_id = {e["id"]: e for e in events}

        # Identify the expected evidence records
        port_4444_ids = {
            e["id"] for e in events
            if str(e.get("dst_port") or "") == "4444"
            or "4444" in str(e.get("command_line") or "")
        }
        assert port_4444_ids, "Expected port 4444 events in fixture"

        pool_3333_flow_ids = {
            e["id"] for e in events
            if e.get("dst_ip") == "192.0.2.250" and str(e.get("dst_port") or "") == "3333"
        }
        kworkerd_ids = {
            e["id"] for e in events
            if "kworkerd" in str(e.get("command_line") or "") and "192.0.2.250:3333" in str(e.get("command_line") or "")
        }
        high_cpu_ids = {
            e["id"] for e in events
            if e.get("event_type") == "metric" and float(e["details"].get("cpu_percent") or 0) > 90
        }
        assert len(pool_3333_flow_ids) >= 1
        assert len(kworkerd_ids) == 1
        assert len(high_cpu_ids) == 10  # 02:15 through 03:00 in 08_system_metrics.csv

        detections = client.get(f"/api/v1/detections/cases/{case_id}/detections").json()
        t1496 = [d for d in detections if d.get("mitre_technique") == "T1496"]
        assert len(t1496) == 1, f"Expected unified T1496 finding, got {t1496}"

        matched = set(t1496[0]["matched_event_ids"])
        # Must include the 192.0.2.250:3333 flow, kworkerd execution, and CPU > 90% samples
        assert pool_3333_flow_ids <= matched
        assert kworkerd_ids <= matched
        assert high_cpu_ids <= matched
        # Must NOT include any port 4444 reverse-shell events
        assert not (matched & port_4444_ids), (
            f"T1496 must not include port 4444 events: {[events_by_id[i] for i in (matched & port_4444_ids)]}"
        )

        # Reverse shell rule still catches /dev/tcp/.../4444 independently
        rev_shell = [d for d in detections if d.get("mitre_technique") == "T1059.004"]
        assert len(rev_shell) >= 1
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
