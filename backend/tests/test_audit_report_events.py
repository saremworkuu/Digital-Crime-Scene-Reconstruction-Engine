import csv
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import uuid
from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app.api.v1 import audit as audit_api
from app.api.v1 import evidence as evidence_module
from app.api.v1 import reports as reports_api
from app.core.dependencies import get_current_user
from app.core.security import hash_password
from app.db.base import Base
import app.db.models  # noqa: F401
from app.db.models.audit_log import AuditLog
from app.db.models.case import Case, CaseStatus
from app.db.models.user import User, UserRole
from app.db.session import get_db
from app.main import app as fastapi_app

WEB_COMPROMISE_DIR = (
    Path(__file__).resolve().parents[1] / "test_evidence" / "web_server_compromise"
)


def test_report_generate_view_and_download_append_audit_rows(monkeypatch):
    case_id = uuid.uuid4()
    user = SimpleNamespace(id=uuid.uuid4())
    added = []
    commits = []

    class FakeDB:
        def add(self, row):
            added.append(row)

        def commit(self):
            commits.append(True)

    db = FakeDB()

    def make_entry(db_arg, user_arg, action, resource, request=None, case_id=None, details=None):
        entry = SimpleNamespace(action=action, resource=resource, case_id=case_id, details=details)
        db_arg.add(entry)
        return entry

    monkeypatch.setattr(reports_api, "log_audit_event", make_entry)
    for action in ("report.generated", "report.viewed", "report.downloaded"):
        reports_api._audit_report_action(db, user, case_id, action, report_id="report-id")

    assert [row.action for row in added] == ["report.generated", "report.viewed", "report.downloaded"]
    assert all(row.resource == "report:report-id" and row.case_id == case_id for row in added)
    assert len(commits) == len(added)


def test_audit_router_exposes_no_edit_or_delete_operations():
    assert all(route.methods == {"GET"} for route in audit_api.router.routes)


def test_audit_response_field_names_match_frontend_contract():
    from app.schemas.audit import AuditLogResponse

    response = AuditLogResponse(
        id=uuid.uuid4(), user_id=uuid.uuid4(), case_id=None, action="report.viewed",
        resource="report:report-id", ip_address=None, user_agent=None, details={"report_id": "report-id"},
        timestamp="2026-10-25T00:00:00Z", user_name="examiner", user_role="investigator",
        target_type="report", target_id="report-id",
    )
    assert response.target_type == "report"
    assert response.target_id == "report-id"
    assert response.user_name == "examiner"


def test_audit_canonical_format_chronological_sort_and_immutability(tmp_path, monkeypatch):
    required = ("01_apache_access.log", "02_auth.log", "03_auditd.log")
    for fname in required:
        assert (WEB_COMPROMISE_DIR / fname).is_file()

    test_db = tmp_path / "audit_norm_test.sqlite"
    engine = create_engine(f"sqlite:///{test_db}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    upload_dir = tmp_path / "evidence_uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(evidence_module, "UPLOAD_DIR", upload_dir)

    db = TestSession()
    user = User(
        username=f"aud_{uuid.uuid4().hex[:8]}",
        email=f"aud_{uuid.uuid4().hex[:8]}@dcsre.test",
        hashed_password=hash_password("Investigator#2026"),
        role=UserRole.INVESTIGATOR,
        is_active=True,
    )
    db.add(user)
    db.flush()
    case = Case(name="Audit Chronology Case", description="Immutability & schema", status=CaseStatus.OPEN, created_by=user.id)
    db.add(case)
    db.commit()
    user_id = user.id
    case_id = case.id

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

    # Track any UPDATE/DELETE SQL hitting audit_log
    audit_mutations: list[str] = []

    @event.listens_for(engine, "before_cursor_execute")
    def _watch_sql(conn, cursor, statement, parameters, context, executemany):
        upper = statement.lstrip().upper()
        if "AUDIT_LOG" in upper and (upper.startswith("UPDATE") or upper.startswith("DELETE")):
            audit_mutations.append(statement)

    try:
        client = TestClient(fastapi_app)
        for fname in required:
            fpath = WEB_COMPROMISE_DIR / fname
            with fpath.open("rb") as fh:
                res = client.post(
                    f"/api/v1/evidence/cases/{case_id}/evidence/upload",
                    files={"file": (fname, fh, "text/plain")},
                    data={"description": fname},
                )
                assert res.status_code == 201, res.text

        # Seed legacy audit rows (out-of-order timestamps on same day + tied timestamps + legacy keys)
        legacy_earlier_inserted_late = AuditLog(
            id=uuid.uuid4(),
            user_id=user_id,
            case_id=case_id,
            action="EVIDENCE_UPLOADED",
            resource="evidence:legacy-1",
            details={
                "file_name": "legacy_apache.log",
                "size_bytes": 1234,
                "sha256": "deadbeef" * 8,
                "parser": "WebAccessParser",
            },
            timestamp=datetime(2026, 7, 22, 15, 43, 0),  # naive same day
        )
        legacy_tie_first = AuditLog(
            id=uuid.uuid4(),
            user_id=user_id,
            case_id=case_id,
            action="EVIDENCE_DELETE",
            resource="evidence:legacy-tie-1",
            details={"filename": "tie1.log", "sha256": "abcd" * 16},
            timestamp=datetime(2026, 7, 22, 18, 0, 0, tzinfo=timezone.utc),
        )
        legacy_tie_second = AuditLog(
            id=uuid.uuid4(),
            user_id=user_id,
            case_id=case_id,
            action="CASE_STATUS_UPDATE",
            resource=f"case:{case_id}",
            details={"from": "open", "to": "closed"},
            timestamp=datetime(2026, 7, 22, 18, 0, 0, tzinfo=timezone.utc),
        )
        legacy_later_inserted_first = AuditLog(
            id=uuid.uuid4(),
            user_id=user_id,
            case_id=case_id,
            action="EVIDENCE_PARSED",
            resource="evidence:legacy-2",
            details={
                "filename": "legacy_audit.log",
                "file_size": 5678,
                "file_type": "text/plain",
                "sha256_hash": "cafebabe" * 8,
                "parser": "AuditdParser",
                "events_extracted": 9,
            },
            timestamp=datetime(2026, 7, 22, 20, 22, 0, tzinfo=timezone.utc),
        )
        db.add_all([
            legacy_later_inserted_first,
            legacy_earlier_inserted_late,
            legacy_tie_first,
            legacy_tie_second,
        ])
        db.commit()

        # 1. Verify new uploaded/parsed rows use dotted lowercase & canonical 6-key details
        logs = client.get(f"/api/v1/audit/logs?case_id={case_id}").json()
        parsed_rows = [row for row in logs if row["action"] == "evidence.parsed" and row["details"].get("filename") in required]
        assert len(parsed_rows) == 3
        parsers_seen = {row["details"]["filename"]: row["details"]["parser"] for row in parsed_rows}
        assert parsers_seen == {
            "01_apache_access.log": "web_access",
            "02_auth.log": "auth_log",
            "03_auditd.log": "auditd",
        }
        expected_keys = {"filename", "file_size", "file_type", "sha256_hash", "parser", "events_extracted"}
        for row in parsed_rows:
            assert expected_keys <= set(row["details"].keys())
            assert isinstance(row["details"]["events_extracted"], int) and row["details"]["events_extracted"] > 0

        # 2. Verify chronological descending ordering (20:22 above 18:00 ties above 15:43) + tie by insertion order
        legacy_ids = {
            str(legacy_later_inserted_first.id),
            str(legacy_tie_first.id),
            str(legacy_tie_second.id),
            str(legacy_earlier_inserted_late.id),
        }
        legacy_order = [row for row in logs if row["id"] in legacy_ids]
        assert [row["id"] for row in legacy_order] == [
            str(legacy_later_inserted_first.id),
            str(legacy_tie_first.id),
            str(legacy_tie_second.id),
            str(legacy_earlier_inserted_late.id),
        ]

        # Legacy display projection must normalize action, sha256 -> sha256_hash, and parser slug
        normalized_legacy = next(r for r in legacy_order if r["id"] == str(legacy_earlier_inserted_late.id))
        assert normalized_legacy["action"] == "evidence.uploaded"
        assert normalized_legacy["details"]["filename"] == "legacy_apache.log"
        assert normalized_legacy["details"]["file_size"] == 1234
        assert normalized_legacy["details"]["sha256_hash"] == "deadbeef" * 8
        assert normalized_legacy["details"]["parser"] == "web_access"
        assert "sha256" not in normalized_legacy["details"]

        # 3. Verify CSV export uses the same chronological order & read-only normalization
        csv_resp = client.get(f"/api/v1/audit/export?case_id={case_id}")
        assert csv_resp.status_code == 200
        csv_rows = list(csv.DictReader(io.StringIO(csv_resp.text)))
        csv_legacy = [r for r in csv_rows if r["ID"] in legacy_ids]
        assert [r["ID"] for r in csv_legacy] == [row["id"] for row in legacy_order]
        csv_norm = next(r for r in csv_legacy if r["ID"] == str(legacy_earlier_inserted_late.id))
        assert csv_norm["Action"] == "evidence.uploaded"
        assert json.loads(csv_norm["Details_JSON"])["sha256_hash"] == "deadbeef" * 8

        # 4. Prove stored DB rows in audit_log were NEVER updated or deleted
        assert audit_mutations == []
        db.expire_all()
        stored_legacy = db.scalar(select(AuditLog).where(AuditLog.id == legacy_earlier_inserted_late.id))
        assert stored_legacy.action == "EVIDENCE_UPLOADED"
        assert stored_legacy.details["sha256"] == "deadbeef" * 8
        assert stored_legacy.details["parser"] == "WebAccessParser"

        # 5. Verify report uploader_name matches audit user_name (never "Forensics Examiner"),
        # report uploaded_at matches audit received_at, parsed_at is recorded, and report.exported
        # carries report_id, version, report_hash, format.
        ev_upload_rows = [
            r for r in logs
            if r["action"] == "evidence.uploaded" and r["details"].get("filename") == "01_apache_access.log"
        ]
        ev_parse_rows = [
            r for r in logs
            if r["action"] == "evidence.parsed" and r["details"].get("filename") == "01_apache_access.log"
        ]
        assert len(ev_upload_rows) == 1 and len(ev_parse_rows) == 1
        assert ev_upload_rows[0]["user_name"] == user.username
        assert ev_upload_rows[0]["details"].get("received_at")
        assert ev_parse_rows[0]["details"].get("received_at") == ev_upload_rows[0]["details"]["received_at"]
        assert ev_parse_rows[0]["details"].get("parsed_at")

        gen_resp = client.get(f"/api/v1/reports/cases/{case_id}/report")
        assert gen_resp.status_code == 200, gen_resp.text
        report_json = gen_resp.json()
        custody_apache = next(c for c in report_json["chain_of_custody"] if c["filename"] == "01_apache_access.log")
        assert custody_apache["uploaded_by"] == user.username
        assert custody_apache["uploaded_at"] == ev_upload_rows[0]["timestamp"]
        assert custody_apache["received_at"] == ev_upload_rows[0]["timestamp"]
        assert custody_apache.get("parsed_at") is not None

        export_resp = client.get(f"/api/v1/reports/cases/{case_id}/reports/html")
        assert export_resp.status_code == 200
        logs_after_export = client.get(f"/api/v1/audit/logs?case_id={case_id}").json()
        export_audit = next(r for r in logs_after_export if r["action"] == "report.exported")
        assert export_audit["details"]["report_id"] == report_json["id"]
        assert export_audit["details"]["version"] == report_json["version"]
        assert export_audit["details"]["report_hash"] == report_json["report_hash"]
        assert export_audit["details"]["format"] == "html"

        # 6. Legal hold blocks deletion; releasing legal hold deletes case with details
        db_case = db.get(Case, case_id)
        db_case.legal_hold = True
        db.commit()
        blocked_del = client.delete(f"/api/v1/cases/{case_id}")
        assert blocked_del.status_code == 400
        assert "legal hold" in blocked_del.json()["detail"].lower()

        db_case = db.get(Case, case_id)
        db_case.legal_hold = False
        db.commit()
        del_resp = client.delete(f"/api/v1/cases/{case_id}")
        assert del_resp.status_code == 200
        logs_after_del = client.get(f"/api/v1/audit/logs?case_id={case_id}").json()
        del_audit = next(r for r in logs_after_del if r["action"] == "case.deleted")
        assert del_audit["details"]["case_name"] == "Audit Chronology Case"
        assert del_audit["details"]["evidence_count"] == 3
        assert del_audit["details"]["event_count"] > 0
    finally:
        event.remove(engine, "before_cursor_execute", _watch_sql)
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
