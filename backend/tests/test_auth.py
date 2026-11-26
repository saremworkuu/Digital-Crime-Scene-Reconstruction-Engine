import pytest
from fastapi import HTTPException
from app.api.v1.auth import validate_real_email


def test_valid_real_emails():
    valid_list = [
        "felixbrown27@gmail.com",
        "investigator@agency.gov",
        "sarah.connor@cyberdefense.org",
        "detective_miller@police.ny.gov",
        "forensics@company.io",
    ]
    for email in valid_list:
        # Should not raise
        validate_real_email(email)


def test_disposable_emails_rejected():
    disposable_list = [
        "john@tempmail.com",
        "agent@mailinator.com",
        "user123@yopmail.com",
        "secret@10minutemail.com",
        "hacker@trashmail.com",
    ]
    for email in disposable_list:
        with pytest.raises(HTTPException) as exc_info:
            validate_real_email(email)
        assert exc_info.value.status_code == 400
        assert "disposable" in exc_info.value.detail.lower() or "not permitted" in exc_info.value.detail.lower()


def test_fake_and_placeholder_domains_rejected():
    fake_domains = [
        "person@test.com",
        "user@example.com",
        "forensics@fake.com",
        "agent@sample.com",
        "detective@asdf.com",
    ]
    for email in fake_domains:
        with pytest.raises(HTTPException) as exc_info:
            validate_real_email(email)
        assert exc_info.value.status_code == 400
        assert "not allowed" in exc_info.value.detail.lower() or "placeholder" in exc_info.value.detail.lower()


def test_fake_usernames_rejected():
    fake_usernames = [
        "test@gmail.com",
        "fake@yahoo.com",
        "dummy@outlook.com",
        "asdf@agency.gov",
        "qwerty@corp.net",
    ]
    for email in fake_usernames:
        with pytest.raises(HTTPException) as exc_info:
            validate_real_email(email)
        assert exc_info.value.status_code == 400
        assert "placeholder" in exc_info.value.detail.lower() or "not permitted" in exc_info.value.detail.lower()


def test_syntax_and_missing_tld_rejected():
    invalid_syntax = [
        "plainaddress",
        "@missinguser.com",
        "missingdomain@",
        "user@domain",
        "a@b.c",
    ]
    for email in invalid_syntax:
        with pytest.raises(HTTPException) as exc_info:
            validate_real_email(email)
        assert exc_info.value.status_code == 400


def test_update_profile_schema_validation():
    from app.schemas.auth import UpdateProfileRequest

    req = UpdateProfileRequest(
        name="Agent Mulder",
        email="mulder@fbi.gov",
        department="X-Files Unit",
        badge_id="FBI-90210"
    )
    assert req.name == "Agent Mulder"
    assert req.email == "mulder@fbi.gov"
    assert req.department == "X-Files Unit"
    assert req.badge_id == "FBI-90210"
    assert req.badgeId == "FBI-90210"


def test_change_password_updates_hash_revokes_old_token_and_rotates_access_token(tmp_path):
    import uuid
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.main import app as fastapi_app
    from app.core.security import create_access_token, hash_password
    from app.db.base import Base
    import app.db.models  # noqa: F401
    from app.db.models.user import User, UserRole
    from app.db.session import get_db

    test_db = tmp_path / "auth_pw.sqlite"
    engine = create_engine(f"sqlite:///{test_db}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    db = TestSession()
    user = User(
        username=f"examiner_{uuid.uuid4().hex[:6]}",
        email="examiner@agency.gov",
        hashed_password=hash_password("OldPass#2026"),
        role=UserRole.INVESTIGATOR,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    def override_get_db():
        s = TestSession()
        try:
            yield s
        finally:
            s.close()

    prev_db = fastapi_app.dependency_overrides.get(get_db)
    fastapi_app.dependency_overrides[get_db] = override_get_db

    try:
        client = TestClient(fastapi_app)
        old_token = create_access_token({"sub": str(user.id), "role": "investigator"})
        headers = {"Authorization": f"Bearer {old_token}"}

        # Wrong current password rejected
        bad_pw = client.post(
            "/api/v1/auth/change-password",
            headers=headers,
            json={"current_password": "WrongPassword1", "new_password": "NewPass#2026"},
        )
        assert bad_pw.status_code == 400

        # Same password rejected
        same_pw = client.post(
            "/api/v1/auth/change-password",
            headers=headers,
            json={"current_password": "OldPass#2026", "new_password": "OldPass#2026"},
        )
        assert same_pw.status_code == 400

        # Valid change succeeds, revokes old token, and returns a working rotated token
        ok_res = client.post(
            "/api/v1/auth/change-password",
            headers=headers,
            json={
                "current_password": "OldPass#2026",
                "new_password": "NewPass#2026",
                "confirm_password": "NewPass#2026",
            },
        )
        assert ok_res.status_code == 200, ok_res.text
        new_token = ok_res.json().get("access_token")
        assert new_token and new_token != old_token

        # Old JWT jti is recorded as revoked
        from jose import jwt as _jwt
        from sqlalchemy import select as _select
        from app.core.config import settings as _settings
        from app.db.models.revoked_token import RevokedToken as _RevokedToken

        old_jti = _jwt.decode(
            old_token,
            _settings.SECRET_KEY,
            algorithms=[_settings.ALGORITHM],
        )["jti"]
        check_db = TestSession()
        try:
            revoked = check_db.execute(
                _select(_RevokedToken).where(_RevokedToken.jti == old_jti)
            ).scalar_one_or_none()
            assert revoked is not None
        finally:
            check_db.close()

        # New JWT remains authenticated
        new_me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {new_token}"})
        assert new_me.status_code == 200

        # Old password is rejected and new password succeeds
        old_login = client.post(
            "/api/v1/auth/login",
            json={"email": "examiner@agency.gov", "password": "OldPass#2026"},
        )
        assert old_login.status_code == 401
        login_res = client.post(
            "/api/v1/auth/login",
            json={"email": "examiner@agency.gov", "password": "NewPass#2026"},
        )
        assert login_res.status_code == 200
    finally:
        if prev_db is not None:
            fastapi_app.dependency_overrides[get_db] = prev_db
        else:
            fastapi_app.dependency_overrides.pop(get_db, None)
        db.close()
        engine.dispose()

