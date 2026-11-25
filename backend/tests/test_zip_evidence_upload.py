import hashlib
import io
import uuid
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.main import app as fastapi_app
from app.core.dependencies import get_current_user
from app.core.security import hash_password
from app.db.base import Base
import app.db.models  # noqa: F401
from app.db.models.audit_log import AuditLog
from app.db.models.case import Case, CaseStatus
from app.db.models.evidence import Evidence, ParsingStatus
from app.db.models.user import User, UserRole
from app.db.session import get_db
from app.api.v1 import evidence as evidence_module


def _setup_test_app(tmp_path, monkeypatch):
    test_db = tmp_path / "zip_upload.sqlite"
    engine = create_engine(f"sqlite:///{test_db}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    upload_dir = tmp_path / "uploads_evidence"
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
        name="ZIP Ingestion Case",
        description="Archive upload test case",
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

    def cleanup():
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

    return TestClient(fastapi_app), TestSession, case, upload_dir, cleanup


def _build_zip_bytes(entries: list[tuple[str, bytes, int | None]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data, ext_attr in entries:
            info = zipfile.ZipInfo(name)
            if ext_attr is not None:
                info.external_attr = ext_attr
            zf.writestr(info, data)
    return buf.getvalue()


def test_zip_upload_extracts_members_preserves_zip_handles_failures_and_sorts_timeline(tmp_path, monkeypatch):
    client, TestSession, case, upload_dir, cleanup = _setup_test_app(tmp_path, monkeypatch)
    try:
        late_log = b"Aug  1 12:00:00 hostA sshd[100]: Accepted publickey for alice from 10.10.0.5 port 51000\n"
        early_log = b"Aug  1 08:00:00 hostA sshd[90]: Failed password for alice from 198.51.100.40 port 41000\n"
        mid_csv = (
            b"timestamp,host,src_ip,dst_ip,dst_port,protocol,bytes\n"
            b"2026-08-01T10:00:00Z,hostA,10.10.0.10,203.0.113.50,443,TCP,1024\n"
        )
        bad_member = b"MZ\x90\x00not_supported_binary"

        zip_bytes = _build_zip_bytes([
            ("bundle/", b"", None),
            ("__MACOSX/._early_auth.log", b"appledouble", None),
            ("bundle/.DS_Store", b"finderjunk", None),
            ("bundle/Thumbs.db", b"thumbjunk", None),
            ("bundle/later_auth.log", late_log, None),
            ("bundle/unsupported.exe", bad_member, None),
            ("bundle/early_auth.log", early_log, None),
            ("bundle/mid_flow.csv", mid_csv, None),
        ])
        expected_zip_sha256 = hashlib.sha256(zip_bytes).hexdigest()

        res = client.post(
            f"/api/v1/evidence/cases/{case.id}/evidence/upload",
            files={"file": ("case_bundle.zip", zip_bytes, "application/zip")},
            data={"description": "Zip upload test"},
        )
        assert res.status_code == 201, res.text
        body = res.json()

        # Original ZIP preserved & hashed with existing SHA-256 logic
        assert body["filename"] == "case_bundle.zip"
        assert body["sha256_hash"] == expected_zip_sha256

        # Background extraction runs and exposes per-member status via status endpoint
        status_res = client.get(f"/api/v1/evidence/cases/{case.id}/evidence/{body['id']}/status")
        assert status_res.status_code == 200, status_res.text
        status_body = status_res.json()
        assert status_body["status"] == "parsed"

        extracted = status_body.get("extracted_results") or []
        extracted_names = [item["filename"] for item in extracted]
        assert extracted_names == ["later_auth.log", "unsupported.exe", "early_auth.log", "mid_flow.csv"]
        assert "__MACOSX" not in str(extracted_names)
        assert ".DS_Store" not in extracted_names
        assert "Thumbs.db" not in extracted_names

        by_name = {item["filename"]: item for item in extracted}
        assert by_name["later_auth.log"]["status"] == "success"
        assert by_name["later_auth.log"]["evidence"]["sha256_hash"] == hashlib.sha256(late_log).hexdigest()
        assert by_name["unsupported.exe"]["status"] == "failed"
        assert by_name["early_auth.log"]["status"] == "success"
        assert by_name["early_auth.log"]["evidence"]["sha256_hash"] == hashlib.sha256(early_log).hexdigest()
        assert by_name["mid_flow.csv"]["status"] == "success"
        assert by_name["mid_flow.csv"]["evidence"]["sha256_hash"] == hashlib.sha256(mid_csv).hexdigest()

        # Verify DB evidence records & audit trail rows
        session = TestSession()
        try:
            ev_rows = session.execute(
                select(Evidence).where(Evidence.case_id == case.id)
            ).scalars().all()
            ev_by_name = {e.filename: e for e in ev_rows}
            assert {"case_bundle.zip", "later_auth.log", "early_auth.log", "mid_flow.csv"} <= set(ev_by_name)
            zip_row = ev_by_name["case_bundle.zip"]
            assert Path(zip_row.file_path).read_bytes() == zip_bytes
            assert zip_row.parsing_status == ParsingStatus.PARSED

            audit_rows = session.execute(
                select(AuditLog).where(AuditLog.case_id == case.id)
            ).scalars().all()
            for fname in ("case_bundle.zip", "later_auth.log", "early_auth.log", "mid_flow.csv"):
                ev_res_key = f"evidence:{ev_by_name[fname].id}"
                actions = {a.action for a in audit_rows if a.resource == ev_res_key}
                assert {"evidence.uploaded", "evidence.parsed"} <= actions
        finally:
            session.close()

        # Verify timeline and events endpoints return events strictly in chronological order
        ev_res = client.get(f"/api/v1/events/cases/{case.id}/events")
        assert ev_res.status_code == 200
        timestamps = [e["timestamp"] for e in ev_res.json()]
        assert len(timestamps) == 3
        assert timestamps == sorted(timestamps)
        assert timestamps[0].startswith("2026-08-01T08:00:00")
        assert timestamps[1].startswith("2026-08-01T10:00:00")
        assert timestamps[2].startswith("2026-08-01T12:00:00")

        tl_res = client.get(f"/api/v1/timeline/cases/{case.id}/timeline")
        assert tl_res.status_code == 200
        tl_timestamps = [e["timestamp"] for e in tl_res.json()]
        assert tl_timestamps == timestamps
    finally:
        cleanup()


def test_zip_slip_traversal_and_symlinks_are_blocked(tmp_path, monkeypatch):
    client, TestSession, case, upload_dir, cleanup = _setup_test_app(tmp_path, monkeypatch)
    try:
        for bad_entry in (
            ("../../outside.log", b"evil", None),
            ("/etc/passwd.log", b"evil", None),
            ("C:\\temp\\evil.log", b"evil", None),
            ("symlink.log", b"/etc/passwd", 0o120777 << 16),
        ):
            zip_bytes = _build_zip_bytes([bad_entry])
            res = client.post(
                f"/api/v1/evidence/cases/{case.id}/evidence/upload",
                files={"file": ("malicious.zip", zip_bytes, "application/zip")},
                data={"description": "Traversal test"},
            )
            assert res.status_code == 400, f"Expected 400 for {bad_entry[0]}, got {res.status_code}: {res.text}"

        session = TestSession()
        try:
            ev_rows = session.execute(select(Evidence).where(Evidence.case_id == case.id)).scalars().all()
            assert ev_rows == []
        finally:
            session.close()
        assert list(upload_dir.glob("*")) == []
    finally:
        cleanup()


def test_zip_bomb_limits_file_count_and_total_uncompressed_size(tmp_path, monkeypatch):
    client, TestSession, case, _upload_dir, cleanup = _setup_test_app(tmp_path, monkeypatch)
    try:
        monkeypatch.setattr(evidence_module, "MAX_ZIP_FILES", 2)
        too_many_zip = _build_zip_bytes([
            ("a.log", b"2026-08-01T01:00:00Z hostA msg1\n", None),
            ("b.log", b"2026-08-01T02:00:00Z hostA msg2\n", None),
            ("c.log", b"2026-08-01T03:00:00Z hostA msg3\n", None),
        ])
        res_count = client.post(
            f"/api/v1/evidence/cases/{case.id}/evidence/upload",
            files={"file": ("many.zip", too_many_zip, "application/zip")},
            data={"description": "Count limit"},
        )
        assert res_count.status_code == 413

        monkeypatch.setattr(evidence_module, "MAX_ZIP_FILES", 100)
        monkeypatch.setattr(evidence_module, "MAX_ZIP_TOTAL_SIZE", 512)
        bomb_zip = _build_zip_bytes([
            ("big.log", b"2026-08-01T01:00:00Z hostA " + b"A" * 2048 + b"\n", None),
        ])
        res_size = client.post(
            f"/api/v1/evidence/cases/{case.id}/evidence/upload",
            files={"file": ("bomb.zip", bomb_zip, "application/zip")},
            data={"description": "Size limit"},
        )
        assert res_size.status_code == 413

        session = TestSession()
        try:
            ev_rows = session.execute(select(Evidence).where(Evidence.case_id == case.id)).scalars().all()
            assert ev_rows == []
        finally:
            session.close()
    finally:
        cleanup()


def _create_second_case(TestSession, owner_id: uuid.UUID, name: str) -> Case:
    session = TestSession()
    try:
        c = Case(
            name=name,
            description=f"Parity case: {name}",
            status=CaseStatus.OPEN,
            created_by=owner_id,
        )
        session.add(c)
        session.commit()
        session.refresh(c)
        return c
    finally:
        session.close()


def _normalize_event_for_parity(ev: dict) -> tuple:
    return (
        ev.get("timestamp"),
        ev.get("event_type"),
        ev.get("source"),
        ev.get("source_file"),
        ev.get("host"),
        ev.get("user"),
        ev.get("action"),
        ev.get("src_ip"),
        ev.get("dst_ip"),
    )


def test_zip_upload_matches_one_by_one_upload_manifest_events_findings_and_indicators(tmp_path, monkeypatch):
    client, TestSession, case_one_by_one, _upload_dir, cleanup = _setup_test_app(tmp_path, monkeypatch)
    try:
        case_zip = _create_second_case(TestSession, case_one_by_one.created_by, "Shuffled ZIP Parity Case")

        # Small realistic synthetic fixtures spanning auth, web access, and netflow (sharing same second)
        auth_bytes = (
            b"Aug  1 10:00:00 app-srv sshd[101]: Failed password for invalid user admin from 203.0.113.77 port 41001 ssh2\n"
            b"Aug  1 10:00:01 app-srv sshd[102]: Failed password for invalid user admin from 203.0.113.77 port 41002 ssh2\n"
            b"Aug  1 10:00:02 app-srv sshd[103]: Failed password for invalid user admin from 203.0.113.77 port 41003 ssh2\n"
            b"Aug  1 10:00:03 app-srv sshd[104]: Failed password for invalid user admin from 203.0.113.77 port 41004 ssh2\n"
            b"Aug  1 10:00:04 app-srv sshd[105]: Failed password for invalid user admin from 203.0.113.77 port 41005 ssh2\n"
            b"Aug  1 10:00:05 app-srv sshd[106]: Accepted password for operator from 203.0.113.77 port 41006 ssh2\n"
        )
        web_bytes = (
            b'203.0.113.77 - - [01/Aug/2026:10:00:05 +0000] "GET /login?user=admin%27%20OR%201=1-- HTTP/1.1" 200 512 "-" "sqlmap/1.7"\n'
            b'203.0.113.77 - - [01/Aug/2026:10:00:06 +0000] "GET /shell.php?cmd=id HTTP/1.1" 200 256 "-" "curl/8.0"\n'
        )
        flow_bytes = (
            b"timestamp,host,src_ip,dst_ip,dst_port,protocol,bytes\n"
            b"2026-08-01T10:00:05Z,app-srv,203.0.113.77,10.0.0.15,443,TCP,4096\n"
            b"2026-08-01T10:00:06Z,app-srv,10.0.0.15,198.51.100.99,8443,TCP,1048576\n"
        )

        # Case A: upload one by one
        for fname, content in (
            ("01_auth.log", auth_bytes),
            ("02_web.log", web_bytes),
            ("03_netflow.csv", flow_bytes),
        ):
            r = client.post(
                f"/api/v1/evidence/cases/{case_one_by_one.id}/evidence/upload",
                files={"file": (fname, content, "application/octet-stream")},
            )
            assert r.status_code == 201, r.text

        # Case B: upload as a zip with reversed/shuffled member order
        zip_bytes = _build_zip_bytes([
            ("bundle/03_netflow.csv", flow_bytes, None),
            ("bundle/01_auth.log", auth_bytes, None),
            ("bundle/02_web.log", web_bytes, None),
        ])
        zr = client.post(
            f"/api/v1/evidence/cases/{case_zip.id}/evidence/upload",
            files={"file": ("evidence_bundle.zip", zip_bytes, "application/zip")},
        )
        assert zr.status_code == 201, zr.text
        zbody = zr.json()
        st = client.get(f"/api/v1/evidence/cases/{case_zip.id}/evidence/{zbody['id']}/status")
        assert st.status_code == 200 and st.json()["status"] == "parsed"

        # Compare events endpoints in exact returned order
        ev_a = client.get(f"/api/v1/events/cases/{case_one_by_one.id}/events").json()
        ev_b = client.get(f"/api/v1/events/cases/{case_zip.id}/events").json()
        assert [_normalize_event_for_parity(e) for e in ev_a] == [_normalize_event_for_parity(e) for e in ev_b]

        tl_a = client.get(f"/api/v1/timeline/cases/{case_one_by_one.id}/timeline").json()
        tl_b = client.get(f"/api/v1/timeline/cases/{case_zip.id}/timeline").json()
        assert [_normalize_event_for_parity(e) for e in tl_a] == [_normalize_event_for_parity(e) for e in tl_b]

        # Generate reports for both cases and compare artifacts, SHA-256s, indicators, findings, and timeline
        rep_a_res = client.get(f"/api/v1/reports/{case_one_by_one.id}/report")
        rep_b_res = client.get(f"/api/v1/reports/{case_zip.id}/report")
        assert rep_a_res.status_code == 200, rep_a_res.text
        assert rep_b_res.status_code == 200, rep_b_res.text
        rep_a = rep_a_res.json()
        rep_b = rep_b_res.json()

        manifest_a = [(m["filename"], m["sha256_hash"], m["event_count"]) for m in rep_a["evidence_manifest"]]
        manifest_b = [(m["filename"], m["sha256_hash"], m["event_count"]) for m in rep_b["evidence_manifest"]]
        assert sorted(manifest_a) == sorted(manifest_b)
        assert len(manifest_a) == 3
        assert rep_a["case_snapshot"]["evidence_count"] == rep_b["case_snapshot"]["evidence_count"] == 3

        findings_a = sorted((f["rule_id"], f["mitre_tactic"], f["mitre_technique"], f["severity"]) for f in rep_a["mitre_coverage"])
        findings_b = sorted((f["rule_id"], f["mitre_tactic"], f["mitre_technique"], f["severity"]) for f in rep_b["mitre_coverage"])
        assert findings_a == findings_b

        def _norm_indicator(ind: dict) -> tuple:
            sf = str(ind.get("source_finding") or "")
            # Strip per-case random Detection UUIDs when comparing across separate cases
            if len(sf) == 36 and sf.count("-") == 4:
                sf = "<DETECTION_ID>"
            return (ind.get("type"), ind.get("value"), ind.get("role"), sf, ind.get("source_file"))

        assert [_norm_indicator(i) for i in rep_a["indicators"]] == [
            _norm_indicator(i) for i in rep_b["indicators"]
        ]
        assert "evidence_bundle.zip" not in str(rep_b["indicators"])

        atk_a = [_normalize_event_for_parity(e) for e in rep_a["attack_timeline_summary"]]
        atk_b = [_normalize_event_for_parity(e) for e in rep_b["attack_timeline_summary"]]
        assert atk_a == atk_b
    finally:
        cleanup()


def test_same_second_events_keep_deterministic_order_regardless_of_ingestion_order(tmp_path, monkeypatch):
    from app.services.correlation import correlate_attack_chains

    client, TestSession, case_a, _upload_dir, cleanup = _setup_test_app(tmp_path, monkeypatch)
    try:
        case_b = _create_second_case(TestSession, case_a.created_by, "Reverse Ingestion Order Case")

        apache_same_sec = (
            b'203.0.113.55 - - [01/Aug/2026:12:30:00 +0000] "GET /admin/login?id=1%20UNION%20SELECT HTTP/1.1" 200 400 "-" "curl/8.0"\n'
            b'203.0.113.55 - - [01/Aug/2026:12:30:00 +0000] "POST /upload.php HTTP/1.1" 200 200 "-" "curl/8.0"\n'
        )
        netflow_same_sec = (
            b"timestamp,host,src_ip,dst_ip,dst_port,protocol,bytes\n"
            b"2026-08-01T12:30:00Z,web01,203.0.113.55,10.0.0.5,80,TCP,2048\n"
            b"2026-08-01T12:30:00Z,web01,10.0.0.5,198.51.100.88,443,TCP,8192\n"
        )

        # Case A ingests apache then netflow
        for fname, raw in (("01_apache.log", apache_same_sec), ("02_netflow.csv", netflow_same_sec)):
            assert client.post(
                f"/api/v1/evidence/cases/{case_a.id}/evidence/upload",
                files={"file": (fname, raw, "application/octet-stream")},
            ).status_code == 201

        # Case B ingests netflow then apache
        for fname, raw in (("02_netflow.csv", netflow_same_sec), ("01_apache.log", apache_same_sec)):
            assert client.post(
                f"/api/v1/evidence/cases/{case_b.id}/evidence/upload",
                files={"file": (fname, raw, "application/octet-stream")},
            ).status_code == 201

        events_a = client.get(f"/api/v1/events/cases/{case_a.id}/events").json()
        events_b = client.get(f"/api/v1/events/cases/{case_b.id}/events").json()
        assert [_normalize_event_for_parity(e) for e in events_a] == [_normalize_event_for_parity(e) for e in events_b]

        tl_a = client.get(f"/api/v1/timeline/cases/{case_a.id}/timeline").json()
        tl_b = client.get(f"/api/v1/timeline/cases/{case_b.id}/timeline").json()
        assert [_normalize_event_for_parity(e) for e in tl_a] == [_normalize_event_for_parity(e) for e in tl_b]

        exp_a = client.get(f"/api/v1/timeline/cases/{case_a.id}/timeline/export?format=json").json()
        exp_b = client.get(f"/api/v1/timeline/cases/{case_b.id}/timeline/export?format=json").json()
        assert [(e["timestamp"], e["event_type"], e["source"]) for e in exp_a] == [
            (e["timestamp"], e["event_type"], e["source"]) for e in exp_b
        ]

        rep_a = client.get(f"/api/v1/reports/{case_a.id}/report").json()
        rep_b = client.get(f"/api/v1/reports/{case_b.id}/report").json()
        assert [_normalize_event_for_parity(e) for e in rep_a["attack_timeline_summary"]] == [
            _normalize_event_for_parity(e) for e in rep_b["attack_timeline_summary"]
        ]

        synthetic_dets = [
            {"id": "d1", "mitre_tactic": "Initial Access", "matching_event_ids": [events_a[0]["id"]], "target_host": "web01"},
            {"id": "d2", "mitre_tactic": "Execution", "matching_event_ids": [events_a[1]["id"]], "target_host": "web01"},
            {"id": "d3", "mitre_tactic": "Command and Control", "matching_event_ids": [events_a[2]["id"]], "target_host": "web01"},
            {"id": "d4", "mitre_tactic": "Exfiltration", "matching_event_ids": [events_a[3]["id"]], "target_host": "web01"},
        ]
        chains_a = correlate_attack_chains(events_a, detections=synthetic_dets)
        synthetic_dets_b = [
            {"id": "d1", "mitre_tactic": "Initial Access", "matching_event_ids": [events_b[0]["id"]], "target_host": "web01"},
            {"id": "d2", "mitre_tactic": "Execution", "matching_event_ids": [events_b[1]["id"]], "target_host": "web01"},
            {"id": "d3", "mitre_tactic": "Command and Control", "matching_event_ids": [events_b[2]["id"]], "target_host": "web01"},
            {"id": "d4", "mitre_tactic": "Exfiltration", "matching_event_ids": [events_b[3]["id"]], "target_host": "web01"},
        ]
        chains_b = correlate_attack_chains(events_b, detections=synthetic_dets_b)
        assert chains_a and chains_b
        assert [(e["source_file"], e["source_record_id"], e["action"]) for e in chains_a[0]["events"]] == [
            (e["source_file"], e["source_record_id"], e["action"]) for e in chains_b[0]["events"]
        ]
    finally:
        cleanup()


def test_duplicate_file_and_zip_uploads_do_not_create_duplicate_rows(tmp_path, monkeypatch):
    client, TestSession, case, upload_dir, cleanup = _setup_test_app(tmp_path, monkeypatch)
    try:
        log_bytes = b"Aug  1 09:00:00 hostX sshd[50]: Failed password for alice from 198.51.100.10 port 5000\n"
        r1 = client.post(
            f"/api/v1/evidence/cases/{case.id}/evidence/upload",
            files={"file": ("auth.log", log_bytes, "text/plain")},
        )
        assert r1.status_code == 201
        b1 = r1.json()
        assert b1["duplicate"] is False

        # Re-upload exact same file intentionally or via retry (even under a different filename)
        r2 = client.post(
            f"/api/v1/evidence/cases/{case.id}/evidence/upload",
            files={"file": ("auth_retry.log", log_bytes, "text/plain")},
        )
        assert r2.status_code == 201
        b2 = r2.json()
        assert b2["duplicate"] is True
        assert b2["duplicate_of"] == b1["id"]
        assert b2["id"] == b1["id"]

        # Now upload a ZIP containing the already-ingested log plus one new file, and upload that ZIP twice
        new_csv = b"timestamp,host,src_ip,dst_ip,dst_port,protocol,bytes\n2026-08-01T09:00:05Z,hostX,10.0.0.5,198.51.100.10,443,TCP,512\n"
        zip_bytes = _build_zip_bytes([
            ("auth.log", log_bytes, None),
            ("flow.csv", new_csv, None),
        ])
        z1 = client.post(
            f"/api/v1/evidence/cases/{case.id}/evidence/upload",
            files={"file": ("archive.zip", zip_bytes, "application/zip")},
        )
        assert z1.status_code == 201
        z1_body = z1.json()
        assert z1_body["duplicate"] is False
        z1_status = client.get(f"/api/v1/evidence/cases/{case.id}/evidence/{z1_body['id']}/status").json()
        by_name = {item["filename"]: item for item in z1_status["extracted_results"]}
        assert by_name["auth.log"]["status"] == "duplicate"
        assert by_name["flow.csv"]["status"] == "success"

        # Upload exact same ZIP a second time
        z2 = client.post(
            f"/api/v1/evidence/cases/{case.id}/evidence/upload",
            files={"file": ("archive.zip", zip_bytes, "application/zip")},
        )
        assert z2.status_code == 201
        z2_body = z2.json()
        assert z2_body["duplicate"] is True
        assert z2_body["duplicate_of"] == z1_body["id"]

        session = TestSession()
        try:
            ev_rows = session.execute(select(Evidence).where(Evidence.case_id == case.id)).scalars().all()
            assert len(ev_rows) == 3  # auth.log, archive.zip, flow.csv only (no duplicates)
            dup_audits = session.execute(
                select(AuditLog).where(
                    AuditLog.case_id == case.id,
                    AuditLog.action == "evidence.duplicate_skipped",
                )
            ).scalars().all()
            assert len(dup_audits) >= 3  # auth_retry.log, auth.log inside zip, archive.zip retry
        finally:
            session.close()
    finally:
        cleanup()


def test_zip_container_stored_in_custody_but_excluded_from_indicators_and_manifest(tmp_path, monkeypatch):
    client, TestSession, case, _upload_dir, cleanup = _setup_test_app(tmp_path, monkeypatch)
    try:
        csv_bytes = (
            b"timestamp,host,src_ip,dst_ip,dst_port,protocol,bytes\n"
            b"2026-08-01T14:00:00Z,web02,198.51.100.20,10.0.0.8,443,TCP,1500\n"
        )
        zip_bytes = _build_zip_bytes([("flows.csv", csv_bytes, None)])
        zip_sha = hashlib.sha256(zip_bytes).hexdigest()
        csv_sha = hashlib.sha256(csv_bytes).hexdigest()

        res = client.post(
            f"/api/v1/evidence/cases/{case.id}/evidence/upload",
            files={"file": ("container_only.zip", zip_bytes, "application/zip")},
        )
        assert res.status_code == 201

        rep_res = client.get(f"/api/v1/reports/{case.id}/report")
        assert rep_res.status_code == 200
        rep = rep_res.json()

        manifest_files = [m["filename"] for m in rep["evidence_manifest"]]
        assert manifest_files == ["flows.csv"]
        assert "container_only.zip" not in manifest_files
        assert rep["case_snapshot"]["evidence_count"] == 1

        indicator_values = {(i["type"], i["value"]) for i in rep["indicators"]}
        assert ("file", "flows.csv") in indicator_values
        assert ("file_hash", csv_sha) in indicator_values
        assert ("file", "container_only.zip") not in indicator_values
        assert ("file_hash", zip_sha) not in indicator_values

        custody_by_name = {c["filename"]: c for c in rep["chain_of_custody"]}
        assert "container_only.zip" in custody_by_name
        assert custody_by_name["container_only.zip"]["sha256_hash"] == zip_sha
        assert custody_by_name["container_only.zip"]["is_container"] is True
        assert custody_by_name["flows.csv"]["is_container"] is False
    finally:
        cleanup()
