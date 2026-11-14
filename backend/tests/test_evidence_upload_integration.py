import os
import shutil
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy import create_engine, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.core.config import settings
from app.db.session import get_db
from app.db.models.user import User, UserRole
from app.db.models.case import Case, CaseStatus
from app.db.models.evidence import Evidence
from app.db.models.events import Event
from app.db.models.event_evidence import EventEvidence
from app.api.v1 import evidence as evidence_module


def test_real_auth_evidence_upload(tmp_path, monkeypatch):
    database_url = os.environ.get("DATABASE_URL")

    if not database_url:
        test_db_path = tmp_path / "dcsre_test_db.sqlite"
        database_url = f"sqlite:///{test_db_path}"
        engine = create_engine(database_url, connect_args={"check_same_thread": False})
        from app.db.base import Base
        Base.metadata.create_all(bind=engine)
    else:
        if make_url(database_url).database != "dcsre_test_db":
            pytest.fail(
                "Integration test requires dcsre_test_db. "
                "Refusing to access another database."
            )
        engine = create_engine(database_url)

    TestSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )
    db = TestSession()

    user_id = None
    case_id = None
    upload_dir = tmp_path / "evidence_uploads"

    monkeypatch.setattr(evidence_module, "UPLOAD_DIR", upload_dir)

    def override_get_db():
        session = TestSession()
        try:
            yield session
        finally:
            session.close()

    previous_override = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db

    try:
        # 1. Create a real test user and case.
        user = User(
            username=f"integration_{uuid.uuid4().hex[:12]}",
            email=f"{uuid.uuid4().hex}@example.test",
            hashed_password="not-used-by-this-test",
            role=UserRole.INVESTIGATOR,
            is_active=True,
        )
        db.add(user)
        db.flush()
        user_id = user.id

        case = Case(
            name="Evidence upload integration test",
            description="Temporary test case",
            status=CaseStatus.OPEN,
            created_by=user.id,
        )
        db.add(case)
        db.commit()
        db.refresh(user)
        db.refresh(case)
        case_id = case.id

        # 2. Create a real JWT accepted by the authentication dependency.
        token = jwt.encode(
            {
                "sub": str(user.id),
                "jti": str(uuid.uuid4()),
                "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
            },
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )

        # 3. Upload a Linux authentication log through the actual API.
        sample_log = (
            b"Oct 14 08:30:00 server sshd[1234]: "
            b"Failed password for alice from 192.168.1.20 port 50221 ssh2\n"
            b"Oct 14 08:31:00 server sshd[1235]: "
            b"Accepted password for bob from 192.168.1.10 port 50222 ssh2\n"
            b"Oct 14 08:32:00 server sshd[1236]: "
            b"Invalid user guest from 192.168.1.30\n"
        )

        client = TestClient(app)
        response = client.post(
            "/api/v1/evidence/",
            params={
                "case_id": str(case.id),
                "description": "Integration test authentication log",
            },
            headers={"Authorization": f"Bearer {token}"},
            files={
                "file": (
                    "integration.auth",
                    sample_log,
                    "text/plain",
                )
            },
        )

        assert response.status_code == 201, response.text
        result = response.json()

        assert result["filename"] == "integration.auth"
        assert result["case_id"] == str(case.id)
        assert result["file_size"] == len(sample_log)

        # 4. Verify evidence and parsed events in PostgreSQL.
        db.expire_all()

        evidence = db.get(Evidence, uuid.UUID(result["id"]))
        assert evidence is not None
        assert evidence.case_id == case.id
        assert evidence.file_size == len(sample_log)
        assert evidence.parsing_status == "parsed"
        assert evidence.parser_used == "AuthLogParser"

        events = db.scalars(
            select(Event).where(Event.case_id == case.id)
        ).all()

        assert len(events) == 3
        assert {event.event_type for event in events} == {
            "ssh_failed",
            "ssh_success",
            "invalid_user",
        }

        assert all(event.evidence_id == evidence.id for event in events)

        failed_event = next(
            event for event in events
            if event.event_type == "ssh_failed"
        )
        assert failed_event.details["user"] == "alice"
        assert failed_event.details["source_ip"] == "192.168.1.20"

    finally:
        # 5. Remove associations and test records.
        db.rollback()

        try:
            if case_id is not None:
                event_rows = db.scalars(
                    select(Event).where(Event.case_id == case_id)
                ).all()
                evidence_rows = db.scalars(
                    select(Evidence).where(Evidence.case_id == case_id)
                ).all()

                event_ids = [event.id for event in event_rows]
                evidence_ids = [item.id for item in evidence_rows]

                if event_ids:
                    db.query(EventEvidence).filter(
                        EventEvidence.event_id.in_(event_ids)
                    ).delete(synchronize_session=False)

                if evidence_ids:
                    db.query(EventEvidence).filter(
                        EventEvidence.evidence_id.in_(evidence_ids)
                    ).delete(synchronize_session=False)

                for event in event_rows:
                    db.delete(event)

                for item in evidence_rows:
                    db.delete(item)

                db.flush()

                case = db.get(Case, case_id)
                if case is not None:
                    db.delete(case)

            if user_id is not None:
                user = db.get(User, user_id)
                if user is not None:
                    db.delete(user)

            db.commit()

        finally:
            db.close()
            app.dependency_overrides.pop(get_db, None)
            if previous_override is not None:
                app.dependency_overrides[get_db] = previous_override

            shutil.rmtree(upload_dir, ignore_errors=True)
            engine.dispose()