import base64
import re
import uuid
import zlib
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
from app.db.models.evidence import Evidence, ParsingStatus
from app.db.models.user import User, UserRole
from app.db.session import get_db
from app.api.v1 import evidence as evidence_module
from app.services.report import (
    _compute_report_hash,
    generate_forensic_report_data,
    render_report_html,
    render_report_pdf,
)


STALE_BANNER = "STALE: case changed after this report was generated - regenerate"
NOT_RUN_TEXT = "Analysis not run / no normalized events"


def _extract_pdf_text(pdf_bytes: bytes) -> str:
    """Decompress ReportLab PDF streams (ASCII85 + FlateDecode) with stdlib only."""
    chunks = [pdf_bytes.decode("latin-1", errors="ignore")]
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", pdf_bytes, flags=re.S):
        raw_stream = match.group(1).strip()
        decoded = raw_stream
        if decoded.endswith(b"~>"):
            try:
                decoded = base64.a85decode(decoded[:-2], adobe=False)
            except Exception:
                pass
        try:
            decoded = zlib.decompress(decoded)
        except Exception:
            pass
        text = decoded.decode("latin-1", errors="ignore")
        # Concatenate PDF literal strings inside (...) and collapse whitespace
        literals = " ".join(re.findall(r"\(([^()]*)\)", text))
        literals_joined = "".join(re.findall(r"\(([^()]*)\)", text))
        chunks.append(text)
        if literals:
            chunks.append(re.sub(r"\s+", " ", literals))
        if literals_joined:
            chunks.append(literals_joined)
    return "\n".join(chunks)


def test_report_none_identified_only_when_analysis_ran_and_found_nothing():
    case_dict = {"id": str(uuid.uuid4()), "name": "Clean Case"}
    evidence = [
        {
            "filename": "access.log",
            "sha256_hash": "b" * 64,
            "size_bytes": 120,
            "event_count": 1,
            "uploaded_at": "2026-07-22T00:00:00Z",
            "uploader_name": "investigator",
        }
    ]
    benign_event = {
        "id": "ev-1",
        "timestamp": "2026-07-22T00:00:05Z",
        "event_type": "web_access",
        "source": "access.log",
        "source_file": "access.log",
        "host": "WEB-01",
        "user": "SYSTEM",
        "action": "GET /health 200",
        "severity": "low",
        "is_attack_path": False,
    }

    # Case 1: Analysis ran on normalized events and found no attack/detections -> "None identified"
    ran_clean = generate_forensic_report_data(
        case_dict=case_dict,
        evidence_list=evidence,
        events=[benign_event],
        detections=[],
        analysis_ran=True,
    )
    assert ran_clean["analysis_not_run"] is False
    assert ran_clean["compromised_assets"]["hosts"] == ["None identified"]
    assert ran_clean["remediation"] == [{"action": "None identified", "finding_refs": ""}]
    ran_html = render_report_html(ran_clean)
    assert NOT_RUN_TEXT not in ran_html
    assert "None identified" in ran_html

    # Case 2: Evidence uploaded but 0 normalized events -> "Analysis not run / no normalized events"
    no_events = generate_forensic_report_data(
        case_dict=case_dict,
        evidence_list=[{**evidence[0], "event_count": 0}],
        events=[],
        detections=[],
    )
    assert no_events["analysis_not_run"] is True
    assert no_events["compromised_assets"]["hosts"] == [NOT_RUN_TEXT]
    assert no_events["remediation"] == [{"action": NOT_RUN_TEXT, "finding_refs": ""}]
    no_events_html = render_report_html(no_events)
    no_events_pdf_text = _extract_pdf_text(render_report_pdf(no_events))
    assert NOT_RUN_TEXT in no_events_html
    assert NOT_RUN_TEXT in no_events_pdf_text

    # Case 3: Events present but detections never ran (analysis_ran=False) -> "Analysis not run / no normalized events"
    det_skipped = generate_forensic_report_data(
        case_dict=case_dict,
        evidence_list=evidence,
        events=[benign_event],
        detections=[],
        analysis_ran=False,
    )
    assert det_skipped["analysis_not_run"] is True
    assert NOT_RUN_TEXT in render_report_html(det_skipped)
    assert NOT_RUN_TEXT in _extract_pdf_text(render_report_pdf(det_skipped))


def test_report_stale_flag_and_banner_on_web_server_compromise_upload(tmp_path, monkeypatch):
    repo_root = Path(__file__).resolve().parents[2]
    sample_log = repo_root / "backend" / "test_evidence" / "web_server_compromise" / "01_apache_access.log"
    assert sample_log.is_file(), f"Missing web_server_compromise fixture: {sample_log}"

    test_db = tmp_path / "test_reports.sqlite"
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
        name="Web Server Compromise Stale Test",
        description="Checks stale snapshot banner before and after log ingestion",
        status=CaseStatus.OPEN,
        created_by=user.id,
    )
    db.add(case)
    db.flush()

    # Simulate pre-parse / unanalyzed evidence (1 evidence, 0 events)
    pending_file = upload_dir / "pending.txt"
    pending_file.write_text("placeholder", encoding="utf-8")
    db.add(
        Evidence(
            case_id=case.id,
            uploaded_by=user.id,
            filename="placeholder.txt",
            description="Initial unparsed artifact",
            file_type="text/plain",
            file_path=str(pending_file),
            sha256_hash="0" * 64,
            file_size=11,
            parsing_status=ParsingStatus.PENDING,
        )
    )
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

        # 1. Generate v1.0 BEFORE evidence upload/normalization
        gen_v1 = client.post(f"/api/v1/reports/{case_id}/reports/generate")
        assert gen_v1.status_code == 200, gen_v1.text
        v1_data = gen_v1.json()
        assert v1_data["version"] == "1.0"
        assert v1_data["stale"] is False
        assert v1_data["analysis_not_run"] is True
        assert v1_data["case_snapshot"]["evidence_count"] == 1
        assert v1_data["case_snapshot"]["event_count"] == 0
        assert v1_data["compromised_assets"]["hosts"] == [NOT_RUN_TEXT]
        assert v1_data["remediation"][0]["action"] == NOT_RUN_TEXT
        v1_hash = v1_data["report_hash"]

        # Fresh v1.0 HTML/PDF must NOT have STALE banner, and must show analysis-not-run text
        fresh_html = client.get(f"/api/v1/reports/{case_id}/reports/html")
        assert fresh_html.status_code == 200
        assert STALE_BANNER not in fresh_html.text
        assert NOT_RUN_TEXT in fresh_html.text

        fresh_pdf = client.get(f"/api/v1/reports/{case_id}/reports/pdf")
        assert fresh_pdf.status_code == 200
        fresh_pdf_text = _extract_pdf_text(fresh_pdf.content)
        assert STALE_BANNER not in fresh_pdf_text
        assert NOT_RUN_TEXT in fresh_pdf_text

        # 2. Upload web_server_compromise Apache access log -> parses events + runs detections
        with sample_log.open("rb") as fh:
            upload_res = client.post(
                f"/api/v1/evidence/cases/{case_id}/evidence/upload",
                files={"file": ("01_apache_access.log", fh, "text/plain")},
                data={"description": "Web server compromise access log"},
            )
        assert upload_res.status_code == 201, upload_res.text

        # 3. Saved v1.0 report must now report stale=True and display the STALE banner in HTML & PDF
        stale_json = client.get(f"/api/v1/reports/{case_id}/report")
        assert stale_json.status_code == 200
        stale_payload = stale_json.json()
        assert stale_payload["version"] == "1.0"
        assert stale_payload["stale"] is True
        assert stale_payload["report_hash"] == v1_hash
        assert _compute_report_hash(
            {k: v for k, v in stale_payload.items() if k != "stale"}
        ) == v1_hash

        stale_html = client.get(f"/api/v1/reports/{case_id}/reports/html")
        assert stale_html.status_code == 200
        assert STALE_BANNER in stale_html.text

        stale_pdf = client.get(f"/api/v1/reports/{case_id}/reports/pdf")
        assert stale_pdf.status_code == 200
        assert STALE_BANNER in _extract_pdf_text(stale_pdf.content)

        history_res = client.get(f"/api/v1/reports/{case_id}/reports")
        assert history_res.status_code == 200
        v1_id = history_res.json()[0]["id"]
        assert client.get(f"/api/v1/reports/{case_id}/reports/{v1_id}/data").json()["stale"] is True
        assert STALE_BANNER in client.get(f"/api/v1/reports/{case_id}/reports/{v1_id}/html").text
        assert STALE_BANNER in _extract_pdf_text(
            client.get(f"/api/v1/reports/{case_id}/reports/{v1_id}/pdf").content
        )

        # 4. Regenerate -> v1.1 should NOT be stale and should have no STALE banner
        gen_v2 = client.post(f"/api/v1/reports/{case_id}/reports/generate")
        assert gen_v2.status_code == 200, gen_v2.text
        v2_data = gen_v2.json()
        assert v2_data["version"] == "1.1"
        assert v2_data["stale"] is False
        assert v2_data["analysis_not_run"] is False
        assert v2_data["case_snapshot"]["event_count"] > 0

        latest_v2 = client.get(f"/api/v1/reports/{case_id}/report").json()
        assert latest_v2["version"] == "1.1"
        assert latest_v2["stale"] is False

        v2_html = client.get(f"/api/v1/reports/{case_id}/reports/html")
        assert v2_html.status_code == 200
        assert STALE_BANNER not in v2_html.text

        v2_pdf = client.get(f"/api/v1/reports/{case_id}/reports/pdf")
        assert v2_pdf.status_code == 200
        assert STALE_BANNER not in _extract_pdf_text(v2_pdf.content)
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
