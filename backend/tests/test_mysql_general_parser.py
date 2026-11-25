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
from app.parsers.auth_log import AuthLogParser
from app.parsers.generic_csv_json import GenericCSVJSONParser
from app.parsers.log_parser import LogFileParser
from app.parsers.mysql_general import MySQLGeneralLogParser
from app.parsers.registry import get_parser
from app.schemas.events import EventResponse
from app.services.detection_engine import execute_detections_on_events
from app.services.graph import build_attack_graph
from app.services.normalizer import normalize_records


WEB_COMPROMISE_DIR = (
    Path(__file__).resolve().parents[1] / "test_evidence" / "web_server_compromise"
)


def test_mysql_general_parser_and_sqli_detection():
    log_path = WEB_COMPROMISE_DIR / "05_mysql_general.log"
    assert log_path.is_file(), f"Missing fixture: {log_path}"

    # Registry selects MySQLGeneralLogParser for mysql filenames without changing other dispatch
    assert isinstance(get_parser(log_path), MySQLGeneralLogParser)
    assert isinstance(get_parser(Path("events.csv")), GenericCSVJSONParser)
    assert isinstance(get_parser(Path("auth.auth")), AuthLogParser)

    # Both MySQLGeneralLogParser and LogFileParser fallback produce the 5 clean events
    for parsed in (
        MySQLGeneralLogParser().parse(log_path, original_filename="05_mysql_general.log"),
        LogFileParser().parse(log_path, original_filename="db_general.log"),
    ):
        assert len(parsed) == 5
        normalized = normalize_records(parsed, default_filename="05_mysql_general.log")
        assert len(normalized) == 5

        assert [r["event_type"] for r in normalized] == [
            "db_query",
            "db_query",
            "db_query",
            "db_connect",
            "db_query",
        ]
        assert [r["details"]["thread_id"] for r in normalized] == [208, 209, 211, 240, 240]
        assert normalized[0]["timestamp"] == "2026-07-22T01:25:07.120000Z"
        assert normalized[1]["timestamp"] == "2026-07-22T01:27:20.300000Z"
        assert normalized[2]["timestamp"] == "2026-07-22T01:31:44.512000Z"
        assert normalized[3]["timestamp"] == "2026-07-22T02:15:20Z"
        assert normalized[4]["timestamp"] == "2026-07-22T02:15:21.200000Z"

        # No numeric/thread-id host and no "Query log_event on 208" title
        for rec in normalized:
            host = rec["details"]["host"]
            assert not str(host).isdigit()
            assert host == "unknown_host"
            assert "log_event" not in rec["details"]["action"]

        # Full SQL text preserved in details
        assert "UNION SELECT NULL,NULL,NULL" in normalized[1]["details"]["sql"]
        assert "group_concat(email,0x3a,password_hash)" in normalized[2]["details"]["sql"]
        assert "group_concat(email,0x3a,password_hash)" in normalized[2]["details"]["action"]

        # EventResponse & Graph must never extract thread IDs as hosts
        event_objs = []
        for rec in normalized:
            ev_obj = EventResponse.model_validate({
                "id": uuid.uuid4(),
                "case_id": uuid.uuid4(),
                "evidence_id": uuid.uuid4(),
                "timestamp": rec["timestamp"],
                "event_type": rec["event_type"],
                "source": rec["source"],
                "details": rec["details"],
            })
            assert ev_obj.host == "unknown_host"
            assert ev_obj.model_dump(mode="json")["timestamp"] == rec["timestamp"]
            event_objs.append(ev_obj)

        findings = execute_detections_on_events(event_objs, uuid.uuid4())
        sqli_findings = [
            f for f in findings
            if "sql" in f.get("rule_id", "").lower() or "sql" in f.get("rule_name", "").lower()
        ]
        assert sqli_findings, f"Expected SQLi finding on MySQL events, got {findings}"
        matched_ids = {eid for f in sqli_findings for eid in f.get("matching_event_ids", [])}
        assert str(event_objs[1].id) in matched_ids
        assert str(event_objs[2].id) in matched_ids

        graph = build_attack_graph(event_objs)
        node_labels = {str(n.get("label", "")) for n in graph.get("nodes", [])}
        assert not ({"208", "209", "211", "240"} & node_labels)


def test_mysql_general_single_host_inference_on_upload(tmp_path, monkeypatch):
    mysql_log = WEB_COMPROMISE_DIR / "05_mysql_general.log"
    auth_log = WEB_COMPROMISE_DIR / "02_auth.log"
    assert mysql_log.is_file() and auth_log.is_file()

    test_db = tmp_path / "mysql_test.sqlite"
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
        name="Web Server Compromise MySQL Case",
        description="Tests single-host inference for web_server_compromise/05_mysql_general.log",
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

        # Upload 02_auth.log (single host WEB-01)
        with auth_log.open("rb") as fh:
            r1 = client.post(
                f"/api/v1/evidence/cases/{case_id}/evidence/upload",
                files={"file": ("02_auth.log", fh, "text/plain")},
                data={"description": "Auth log from WEB-01"},
            )
        assert r1.status_code == 201, r1.text

        # Upload 05_mysql_general.log -> infers single host WEB-01
        with mysql_log.open("rb") as fh:
            r2 = client.post(
                f"/api/v1/evidence/cases/{case_id}/evidence/upload",
                files={"file": ("05_mysql_general.log", fh, "text/plain")},
                data={"description": "MySQL general query log"},
            )
        assert r2.status_code == 201, r2.text

        events_res = client.get(f"/api/v1/events/cases/{case_id}/events")
        assert events_res.status_code == 200
        mysql_events = [e for e in events_res.json() if e.get("source") == "mysql_general"]
        assert len(mysql_events) == 5
        assert all(e["host"] == "WEB-01" for e in mysql_events)
        assert all(not str(e["host"]).isdigit() for e in mysql_events)
        assert mysql_events[0]["timestamp"] == "2026-07-22T01:25:07.120000Z"
        assert "UNION SELECT NULL,NULL,NULL" in mysql_events[1]["details"]["sql"]

        det_res = client.get(f"/api/v1/detections/cases/{case_id}/detections")
        assert det_res.status_code == 200
        dets = det_res.json()
        mysql_ids = {e["id"] for e in mysql_events}
        assert any(mysql_ids & set(d.get("matched_event_ids") or []) for d in dets)
        for d in dets:
            for h in (d.get("entities_involved") or {}).get("hosts") or []:
                assert not str(h).isdigit()
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
