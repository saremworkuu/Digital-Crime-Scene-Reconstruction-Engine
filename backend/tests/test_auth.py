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

