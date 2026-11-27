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
from app.parsers.web_access import WebAccessParser
from app.services.normalizer import normalize_records


WEB_COMPROMISE_DIR = (
    Path(__file__).resolve().parents[1] / "test_evidence" / "web_server_compromise"
)


def test_web_access_normalization_keeps_client_ip_in_src_ip_only():
    apache_path = WEB_COMPROMISE_DIR / "01_apache_access.log"
    assert apache_path.is_file()

    records = WebAccessParser().parse(apache_path, original_filename="01_apache_access.log")
    normalized = normalize_records(records, default_filename="01_apache_access.log")
    assert len(normalized) > 0

    for rec in normalized:
        details = rec["details"]
        assert details["host"] == "unknown_host"
        assert details["host_inferred"] is True
        if rec["event_type"] == "web_access":
            assert details.get("src_ip") or details.get("source_ip")
            assert details["host"] != details.get("src_ip")


def test_web_findings_report_target_web01_and_source_203_0_113_140(tmp_path, monkeypatch):
    apache_path = WEB_COMPROMISE_DIR / "01_apache_access.log"
    auth_path = WEB_COMPROMISE_DIR / "02_auth.log"
    assert apache_path.is_file() and auth_path.is_file()

    test_db = tmp_path / "web_findings.sqlite"
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
        name="Web Attribution Case",
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
        # Upload 01_apache_access.log FIRST (before 02_auth.log reveals WEB-01)
        for fname in ("01_apache_access.log", "02_auth.log"):
            fpath = WEB_COMPROMISE_DIR / fname
            with fpath.open("rb") as fh:
                res = client.post(
                    f"/api/v1/evidence/cases/{case.id}/evidence/upload",
                    files={"file": (fname, fh, "text/plain")},
                    data={"description": fname},
                )
                assert res.status_code == 201, res.text

        # Web events must carry resolved server host WEB-01 and client src_ip
        ev_res = client.get(f"/api/v1/events/cases/{case.id}/events")
        assert ev_res.status_code == 200
        web_events = [e for e in ev_res.json() if e.get("event_type") == "web_access"]
        assert len(web_events) > 0
        assert all(e["host"] == "WEB-01" for e in web_events)
        assert any(e.get("src_ip") == "203.0.113.140" for e in web_events)

        det_res = client.get(f"/api/v1/detections/cases/{case.id}/detections")
        assert det_res.status_code == 200
        detections = det_res.json()

        sqli = next(d for d in detections if "sql" in d["rule_name"].lower())
        upload = next(d for d in detections if "upload" in d["rule_name"].lower())
        webshell = next(d for d in detections if "web shell" in d["rule_name"].lower() or "webshell" in d["rule_name"].lower())

        for finding in (sqli, upload, webshell):
            hosts = finding.get("hosts") or []
            entity_hosts = (finding.get("entities_involved") or {}).get("hosts") or []
            source_ips = finding.get("source_ips") or []
            assert "WEB-01" in hosts
            assert "WEB-01" in entity_hosts
            assert "203.0.113.140" not in hosts
            assert "203.0.113.140" not in entity_hosts
            assert "203.0.113.140" in source_ips
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


def test_sqli_merged_finding_counts_first_seen_tactic_and_benign_exclusion(tmp_path, monkeypatch):
    required_files = ("01_apache_access.log", "02_auth.log", "04_waf_alerts.json", "05_mysql_general.log")
    for fname in required_files:
        assert (WEB_COMPROMISE_DIR / fname).is_file(), f"Missing fixture: {fname}"

    test_db = tmp_path / "sqli_merged.sqlite"
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
        name="SQLi Coverage Case",
        description="Apache + WAF + MySQL + Auth",
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
        for fname in required_files:
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
        sqli_findings = [
            d for d in detections
            if "sql" in d["rule_name"].lower() or "sql" in d["rule_id"].lower()
        ]
        assert len(sqli_findings) == 1, f"Expected single merged SQLi finding, got {sqli_findings}"

        sqli = sqli_findings[0]
        assert sqli["mitre_technique"] == "T1190"
        assert sqli["mitre_tactic"] == "Initial Access"
        assert sqli["timestamp"] == "2026-07-22T01:25:07Z"
        assert (sqli.get("rule_information") or {}).get("first_seen") == "2026-07-22T01:25:07Z"
        assert (sqli.get("rule_information") or {}).get("last_seen") == "2026-07-22T01:31:44Z"
        assert "web_sql_injection" in ((sqli.get("rule_information") or {}).get("corroborating_rules") or [])
        assert "WEB-01" in (sqli.get("hosts") or [])
        assert "203.0.113.140" in (sqli.get("source_ips") or [])

        matched_events = [events_by_id[eid] for eid in sqli["matched_event_ids"]]
        apache_matched = [e for e in matched_events if e.get("source_file") == "01_apache_access.log"]
        waf_matched = [e for e in matched_events if e.get("source_file") == "04_waf_alerts.json"]
        mysql_matched = [e for e in matched_events if e.get("source_file") == "05_mysql_general.log"]

        assert len(apache_matched) == 11
        assert len(waf_matched) == 4
        assert len(mysql_matched) == 3
        assert len(matched_events) == 18

        # Ensure credential-dump request is included and benign customer traffic is excluded
        assert any("group_concat" in str(e.get("raw", "")) for e in apache_matched)
        assert not any("/search.php?q=lamp" in str(e.get("raw", "")) for e in matched_events)
        assert not any("192.0.2." in str(e.get("src_ip") or "") for e in matched_events)
        assert not any("SQL_NO_CACHE" in str(e.get("raw", "")) for e in matched_events)
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


def test_netflow_waf_and_findings_resolve_vuln_scan_alias_regardless_of_upload_order(tmp_path, monkeypatch):
    upload_order = [
        "07_netflow_export.csv",
        "04_waf_alerts.json",
        "06_vulnerability_scan_2026-07-15.xml",
    ]
    for fname in upload_order:
        assert (WEB_COMPROMISE_DIR / fname).is_file()

    test_db = tmp_path / "alias_order.sqlite"
    engine = create_engine(f"sqlite:///{test_db}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    upload_dir = tmp_path / "evidence_uploads_alias"
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
        name="Alias Resolution Order Case",
        description="NetFlow + WAF uploaded before VulnScan",
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
        for fname in upload_order:
            fpath = WEB_COMPROMISE_DIR / fname
            with fpath.open("rb") as fh:
                res = client.post(
                    f"/api/v1/evidence/cases/{case.id}/evidence/upload",
                    files={"file": (fname, fh, "text/plain")},
                    data={"description": fname},
                )
                assert res.status_code == 201, res.text

        events = client.get(f"/api/v1/events/cases/{case.id}/events").json()
        netflow_rows = [e for e in events if e.get("source_file") == "07_netflow_export.csv"]
        waf_rows = [e for e in events if e.get("source_file") == "04_waf_alerts.json"]
        assert netflow_rows and waf_rows

        for row in netflow_rows:
            assert row.get("host") == "WEB-01"
            assert row.get("src_ip")
            assert row.get("dst_ip")
        for row in waf_rows:
            assert row.get("host") == "WEB-01"
            assert row.get("src_ip") != "WEB-01"

        detections = client.get(f"/api/v1/detections/cases/{case.id}/detections").json()
        assert detections
        for det in detections:
            assert "10.40.1.15" not in (det.get("source_ips") or []), det
            assert "10.40.1.15" not in (det.get("hosts") or []), det

        graph = client.get(f"/api/v1/graph/cases/{case.id}/graph").json()
        node_labels = [n["label"] for n in graph["nodes"]]
        assert node_labels.count("WEB-01") == 1
        assert "10.40.1.15" not in node_labels
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
