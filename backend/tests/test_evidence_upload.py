from unittest.mock import patch
import uuid
from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.main import app
from app.core.dependencies import get_current_user
from app.db.session import get_db
from app.db.models.case import Case, CaseStatus
from app.db.models.evidence import Evidence, ParsingStatus
from app.db.models.user import User


client = TestClient(app)


def test_upload_evidence_case_not_found():
    """Uploading evidence to a nonexistent case should return 404."""

    fake_user = MagicMock(spec=User)
    fake_user.id = uuid.uuid4()

    fake_db = MagicMock()

    # Simulate a case that doesn't exist.
    fake_db.execute.return_value.scalar_one_or_none.return_value = None

    app.dependency_overrides[get_current_user] = lambda: fake_user
    app.dependency_overrides[get_db] = lambda: fake_db

    try:
        response = client.post(
            "/api/v1/evidence/",
            params={"case_id": str(uuid.uuid4())},
            files={
                "file": (
                    "sample.log",
                    b"Successful login for alice",
                    "text/plain",
                )
            },
            data={"description": "Test evidence"},
        )

        assert response.status_code == 404
        assert response.json()["detail"] == "Case not found."

    finally:
        app.dependency_overrides.clear()


# A 403 Forbidden response means the case exists, but the current user is not allowed to add evidence to it.

def test_upload_evidence_forbidden_for_non_owner():
    """A user must not upload evidence to another user's case."""

    fake_user = MagicMock(spec=User)
    fake_user.id = uuid.uuid4()

    fake_case = MagicMock(spec=Case)
    fake_case.id = uuid.uuid4()
    fake_case.created_by = uuid.uuid4()  # Different user
    fake_case.status = CaseStatus.OPEN

    fake_db = MagicMock()
    fake_db.execute.return_value.scalar_one_or_none.return_value = fake_case

    app.dependency_overrides[get_current_user] = lambda: fake_user
    app.dependency_overrides[get_db] = lambda: fake_db

    try:
        response = client.post(
            "/api/v1/evidence/",
            params={"case_id": str(fake_case.id)},
            files={
                "file": (
                    "sample.log",
                    b"Successful login for alice",
                    "text/plain",
                )
            },
            data={"description": "Test evidence"},
        )

        assert response.status_code == 403
        assert response.json()["detail"] == (
            "You are not authorized to add evidence to this case."
        )

    finally:
        app.dependency_overrides.clear()




def test_upload_evidence_rejects_unsupported_extension():
    """Unsupported file types should be rejected."""

    fake_user = MagicMock(spec=User)
    fake_user.id = uuid.uuid4()

    fake_case = MagicMock(spec=Case)
    fake_case.id = uuid.uuid4()
    fake_case.created_by = fake_user.id
    fake_case.status = CaseStatus.OPEN

    fake_db = MagicMock()
    fake_db.execute.return_value.scalar_one_or_none.return_value = fake_case

    app.dependency_overrides[get_current_user] = lambda: fake_user
    app.dependency_overrides[get_db] = lambda: fake_db

    try:
        response = client.post(
            "/api/v1/evidence/",
            params={"case_id": str(fake_case.id)},
            files={
                "file": (
                    "malware.exe",
                    b"not a supported evidence file",
                    "application/octet-stream",
                )
            },
            data={"description": "Unsupported file test"},
        )

        assert response.status_code == 400
        assert response.json()["detail"] == "Unsupported file extension."

        # The endpoint should reject the file before creating an evidence row.
        fake_db.add.assert_not_called()
        fake_db.commit.assert_not_called()

    finally:
        app.dependency_overrides.clear()




def test_upload_evidence_rejects_closed_case():
    """Evidence cannot be added to a closed case."""

    fake_user = MagicMock(spec=User)
    fake_user.id = uuid.uuid4()

    fake_case = MagicMock(spec=Case)
    fake_case.id = uuid.uuid4()
    fake_case.created_by = fake_user.id
    fake_case.status = CaseStatus.CLOSED

    fake_db = MagicMock()
    fake_db.execute.return_value.scalar_one_or_none.return_value = fake_case

    app.dependency_overrides[get_current_user] = lambda: fake_user
    app.dependency_overrides[get_db] = lambda: fake_db

    try:
        response = client.post(
            "/api/v1/evidence/",
            params={"case_id": str(fake_case.id)},
            files={
                "file": (
                    "sample.log",
                    b"Successful login for alice",
                    "text/plain",
                )
            },
            data={"description": "Closed case test"},
        )

        assert response.status_code == 409
        assert response.json()["detail"] == "Cannot add evidence to a closed case."

        fake_db.add.assert_not_called()
        fake_db.commit.assert_not_called()

    finally:
        app.dependency_overrides.clear()





def test_upload_evidence_rejects_oversized_file(tmp_path):
    """Files larger than 100 MB should be rejected."""

    fake_user = MagicMock(spec=User)
    fake_user.id = uuid.uuid4()

    fake_case = MagicMock(spec=Case)
    fake_case.id = uuid.uuid4()
    fake_case.created_by = fake_user.id
    fake_case.status = CaseStatus.OPEN

    fake_db = MagicMock()
    fake_db.execute.return_value.scalar_one_or_none.return_value = fake_case

    app.dependency_overrides[get_current_user] = lambda: fake_user
    app.dependency_overrides[get_db] = lambda: fake_db

    try:
        with patch("app.api.v1.evidence.UPLOAD_DIR", tmp_path):
            with patch(
                "app.api.v1.evidence.UploadFile.read",
                autospec=True,
                return_value=b"x" * (1024 * 1024),
            ) as mock_read:
                # Simulate the file-size counter already exceeding the limit
                # immediately before the endpoint checks it.
                with patch(
                    "app.api.v1.evidence.MAX_FILE_SIZE",
                    0,
                ):
                    response = client.post(
                        "/api/v1/evidence/",
                        params={"case_id": str(fake_case.id)},
                        files={
                            "file": (
                                "large.log",
                                b"placeholder",
                                "text/plain",
                            )
                        },
                        data={"description": "Oversized file test"},
                    )

        assert response.status_code == 413
        assert response.json()["detail"] == "File exceeds the 100 MB limit."
        fake_db.add.assert_not_called()
        fake_db.commit.assert_not_called()
        

    finally:
        app.dependency_overrides.clear()


