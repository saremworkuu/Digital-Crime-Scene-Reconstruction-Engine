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
from app.parsers.registry import get_parser
from app.services.detection_engine import execute_detections_on_events
from app.services.graph import build_attack_graph
from app.services.normalizer import normalize_records


WEB_COMPROMISE_DIR = (
    Path(__file__).resolve().parents[1] / "test_evidence" / "web_server_compromise"
)

COMMAND_AND_PROCESS_NAMES = {
    "kworkerd",
    "mysqldump",
    "crontab",
    "useradd",
    "usermod",
    "scp",
    "bash",
    "sh",
    "sudo",
    "sshd",
    "vim",
    "curl",
    "wget",
    "chmod",
    "history",
}


def test_web_server_compromise_graph_excludes_commands_and_numeric_hosts():
    events = []
    for path in sorted(WEB_COMPROMISE_DIR.iterdir()):
        if not path.is_file():
            continue
        parser = get_parser(path, original_filename=path.name)
        records = parser.parse(path, original_filename=path.name)
        for rec in normalize_records(records, default_filename=path.name):
            rec["id"] = str(uuid.uuid4())
            events.append(rec)

    findings = execute_detections_on_events(events, uuid.uuid4())
    graph = build_attack_graph(events, attack_path_only=False, findings=findings)

    assert set(graph.keys()) == {"nodes", "edges"}
    nodes = graph["nodes"]
    assert {n["type"] for n in nodes} <= {"host", "ip", "user"}

    labels = {n["label"] for n in nodes}
    # Expected hosts, IPs, and users must still exist
    for expected in ("WEB-01", "10.40.1.30", "203.0.113.140", "opsadmin", "www-data", "sysupdate"):
        assert expected in labels, f"Missing expected graph node: {expected}"

    # No node label may equal a process/command name or a numeric DB thread ID
    lower_labels = {lbl.casefold() for lbl in labels}
    assert not (lower_labels & COMMAND_AND_PROCESS_NAMES)
    assert not any(lbl.isdigit() for lbl in labels)

    # Process names/commands stay attached as attributes on host/user nodes
    root_node = next(n for n in nodes if n["label"] == "root")
    root_processes = (root_node.get("details") or {}).get("processes", [])
    assert "kworkerd" not in labels
    assert any("kworkerd" in str(p) for p in root_processes)


def test_graph_filters_legacy_command_users_and_numeric_hosts_and_preserves_api_shape(tmp_path, monkeypatch):
    # Legacy/raw events that explicitly put commands in `user` and thread IDs in `host`
    legacy_events = [
        {
            "id": "e1",
            "timestamp": "2026-07-22T02:11:00Z",
            "event_type": "auditd",
            "details": {
                "host": "WEB-01",
                "user": "kworkerd",
                "process": "kworkerd",
                "command_line": "kworkerd --pool 192.0.2.250:3333",
            },
            "severity": "high",
        },
        {
            "id": "e2",
            "timestamp": "2026-07-22T02:15:20Z",
            "event_type": "auditd",
            "details": {
                "host": "WEB-01",
                "user": "mysqldump",
                "comm": "mysqldump",
                "command_line": "mysqldump -u root shopdb customers",
            },
            "severity": "high",
        },
        {
            "id": "e3",
            "timestamp": "2026-07-22T02:10:40Z",
            "event_type": "auditd",
            "details": {
                "host": "WEB-01",
                "user": "crontab",
                "exe": "/usr/bin/crontab",
                "command_line": "crontab /tmp/.cron",
            },
            "severity": "high",
        },
        {
            "id": "e4",
            "timestamp": "2026-07-22T01:58:11Z",
            "event_type": "auditd",
            "details": {
                "host": "WEB-01",
                "user": "useradd",
                "command_line": "useradd -m -s /bin/bash sysupdate",
            },
            "severity": "high",
        },
        {
            "id": "e5",
            "timestamp": "2026-07-22T01:36:10Z",
            "event_type": "db_query",
            "details": {
                "host": "208",
                "thread_id": "208",
                "user": None,
            },
            "severity": "high",
        },
    ]

    graph = build_attack_graph(legacy_events)
    labels = {n["label"] for n in graph["nodes"]}
    assert "WEB-01" in labels
    assert not (labels & {"kworkerd", "mysqldump", "crontab", "useradd", "208"})
    web_node = next(n for n in graph["nodes"] if n["label"] == "WEB-01")
    details = web_node.get("details") or {}
    assert set(details.get("processes", [])) >= {"kworkerd", "mysqldump", "crontab"}
    assert "kworkerd --pool 192.0.2.250:3333" in details.get("commands", [])

    # Also verify /api/v1/cases/{case_id}/graph preserves JSON shape & attack_path_only
    test_db = tmp_path / "graph_test.sqlite"
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
    case = Case(name="Graph Sample Case", description="Web compromise", status=CaseStatus.OPEN, created_by=user.id)
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
        for fname in ("01_apache_access.log", "02_auth.log", "03_auditd.log", "05_mysql_general.log", "07_netflow_export.csv"):
            fpath = WEB_COMPROMISE_DIR / fname
            with fpath.open("rb") as fh:
                res = client.post(
                    f"/api/v1/evidence/cases/{case.id}/evidence/upload",
                    files={"file": (fname, fh, "text/plain")},
                    data={"description": fname},
                )
                assert res.status_code == 201, res.text

        full_resp = client.get(f"/api/v1/cases/{case.id}/graph")
        assert full_resp.status_code == 200
        full_data = full_resp.json()
        assert set(full_data.keys()) == {"nodes", "edges"}
        api_labels = {n["label"] for n in full_data["nodes"]}
        for expected in ("WEB-01", "10.40.1.30", "203.0.113.140", "opsadmin", "www-data", "sysupdate"):
            assert expected in api_labels
        assert not ({lbl.casefold() for lbl in api_labels} & COMMAND_AND_PROCESS_NAMES)
        assert not any(lbl.isdigit() for lbl in api_labels)
        api_web_node = next(n for n in full_data["nodes"] if n["label"] == "WEB-01")
        assert any("kworkerd" in str(p) for p in (api_web_node.get("details") or {}).get("processes", []))

        benign_ext_nodes = [
            n for n in full_data["nodes"]
            if n["type"] == "ip"
            and n.get("role") == "external_ip"
            and not n.get("is_compromised")
            and not n.get("is_attack_path")
        ]
        assert len(benign_ext_nodes) >= 20

        attack_resp = client.get(f"/api/v1/cases/{case.id}/graph?attack_path_only=true")
        assert attack_resp.status_code == 200
        attack_data = attack_resp.json()
        assert set(attack_data.keys()) == {"nodes", "edges"}
        assert len(attack_data["nodes"]) < len(full_data["nodes"])
        attack_labels = {n["label"] for n in attack_data["nodes"]}
        assert "WEB-01" in attack_labels
        assert "203.0.113.140" in attack_labels
        assert not (attack_labels & {n["label"] for n in benign_ext_nodes})
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
