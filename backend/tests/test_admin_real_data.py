import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.dependencies import get_current_user
from app.core.permissions import require_admin
from app.core.security import hash_password
from app.db.base import Base
import app.db.models  # noqa: F401
from app.db.models.audit_log import AuditLog
from app.db.models.case import Case, CaseStatus
from app.db.models.evidence import Evidence, ParsingStatus
from app.db.models.sigma_rule import SigmaRule
from app.db.models.user import User, UserRole
from app.db.seed_admin_data import seed_admin_data
from app.db.session import get_db
from app.main import app as fastapi_app


def _setup_admin_test_app(tmp_path):
    test_db = tmp_path / "admin_real_data.sqlite"
    engine = create_engine(f"sqlite:///{test_db}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    db = TestSession()
    admin_user = User(
        username="real_admin",
        email="real_admin@agency.gov",
        hashed_password=hash_password("Admin@2026!"),
        role=UserRole.ADMIN,
        is_active=True,
        status="active",
        sessions=[],
    )
    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)

    def _override_get_db():
        session = TestSession()
        try:
            yield session
        finally:
            session.close()

    def _override_admin():
        return admin_user

    fastapi_app.dependency_overrides[get_db] = _override_get_db
    fastapi_app.dependency_overrides[get_current_user] = _override_admin
    fastapi_app.dependency_overrides[require_admin] = _override_admin

    client = TestClient(fastapi_app)
    return client, db, admin_user, engine


def test_admin_system_health_and_summary_have_no_fake_baselines(tmp_path):
    client, db, admin_user, engine = _setup_admin_test_app(tmp_path)
    try:
        health_res = client.get("/api/v1/admin/system/health")
        assert health_res.status_code == 200
        health = health_res.json()

        assert health["storage_used_bytes"] == 0
        assert health["storage_total_bytes"] > 0
        assert health["failed_logins_24h"] == 0
        assert health["queue"] == []
        assert health["recent_errors"] == []
        assert all(p["files_processed"] == 0 for p in health["parsers"])

        summary_res = client.get("/api/v1/admin/system/summary")
        assert summary_res.status_code == 200
        summary = summary_res.json()
        assert summary["users"] == 1
        assert summary["cases"] == 0
        assert summary["evidence"] == 0
        assert summary["failures"] == 0
        assert summary["new_messages"] == 0
        assert summary["failed_logins_24h"] == 0
        assert summary["queue"] == []

        # Adding a real failed evidence row populates queue and recent_errors dynamically
        case = Case(
            name="Real Incident 01",
            description="Real case",
            created_by=admin_user.id,
            status=CaseStatus.OPEN,
        )
        db.add(case)
        db.flush()
        ev = Evidence(
            case_id=case.id,
            uploaded_by=admin_user.id,
            filename="broken_log.txt",
            file_type="txt",
            file_path=str(tmp_path / "broken_log.txt"),
            sha256_hash="a" * 64,
            file_size=2048,
            parsing_status=ParsingStatus.FAILED,
            parser_used="TextFileParser",
            parsing_error="Malformed UTF-8 byte sequence",
        )
        db.add(ev)
        db.commit()

        health_after = client.get("/api/v1/admin/system/health").json()
        assert health_after["storage_used_bytes"] == 2048
        assert len(health_after["queue"]) == 1
        assert health_after["queue"][0]["file_name"] == "broken_log.txt"
        assert health_after["recent_errors"][0]["message"] == "Malformed UTF-8 byte sequence"
    finally:
        fastapi_app.dependency_overrides.clear()
        db.close()
        engine.dispose()


def test_seed_admin_data_does_not_insert_fake_users_rules_or_messages(tmp_path):
    client, db, _admin_user, engine = _setup_admin_test_app(tmp_path)
    try:
        seed_admin_data(db)

        assert client.get("/api/v1/admin/users").json()[0]["sessions"] == []
        assert len(client.get("/api/v1/admin/users").json()) == 1
        assert client.get("/api/v1/admin/rules").json() == []
        assert client.get("/api/v1/admin/messages").json()["messages"] == []
        assert client.get("/api/v1/admin/messages/count").json()["count"] == 0
        assert client.post("/api/v1/admin/system/reset-demo").status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()
        db.close()
        engine.dispose()


def test_batched_admin_cases_evidence_audit_and_rule_testing(tmp_path):
    client, db, admin_user, engine = _setup_admin_test_app(tmp_path)
    try:
        case = Case(
            name="Batch Test Case",
            description="Batch query test",
            created_by=admin_user.id,
            status=CaseStatus.OPEN,
        )
        db.add(case)
        db.flush()

        for i in range(3):
            db.add(
                Evidence(
                    case_id=case.id,
                    uploaded_by=admin_user.id,
                    filename=f"sample_{i}.log",
                    file_type="log",
                    file_path=str(tmp_path / f"sample_{i}.log"),
                    sha256_hash=f"{i}" * 64,
                    file_size=512,
                    parsing_status=ParsingStatus.PARSED,
                    parser_used="LogFileParser",
                )
            )
            db.add(
                AuditLog(
                    id=uuid.uuid4(),
                    user_id=admin_user.id,
                    case_id=case.id,
                    action="evidence.uploaded",
                    resource=f"evidence:{i}",
                    ip_address="127.0.0.1",
                    details={"filename": f"sample_{i}.log"},
                    timestamp=datetime.now(timezone.utc),
                )
            )

        rule = SigmaRule(
            id="sig-real-1",
            name="Custom Empty Check",
            severity="high",
            mitre_id="T1059",
            enabled=True,
            times_triggered=0,
            description="Real event check",
            query='command_line contains "never_seen_pattern_xyz"',
        )
        db.add(rule)
        db.commit()

        cases = client.get("/api/v1/admin/cases").json()
        assert len(cases) == 1
        assert cases[0]["evidence_count"] == 3
        assert cases[0]["owner"] == "real_admin"

        evidence = client.get("/api/v1/admin/evidence").json()
        assert len(evidence) == 3

        audit_page = client.get("/api/v1/admin/audit?page=1&limit=2").json()
        assert audit_page["total"] == 3
        assert len(audit_page["entries"]) == 2
        assert audit_page["totalPages"] == 2

        test_rule = client.post("/api/v1/admin/rules/sig-real-1/test").json()
        assert test_rule["matchCount"] == 0
        assert test_rule["sampleMatches"] == []
    finally:
        fastapi_app.dependency_overrides.clear()
        db.close()
        engine.dispose()
