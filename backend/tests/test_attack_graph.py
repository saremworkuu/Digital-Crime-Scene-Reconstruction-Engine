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
        assert "198.51.100.201" in attack_labels
        assert "192.0.2.250" in attack_labels
        assert not (attack_labels & {n["label"] for n in benign_ext_nodes})

        node_by_label = {n["label"]: n for n in attack_data["nodes"]}
        assert node_by_label["198.51.100.201"]["role"] == "payload_host"
        assert node_by_label["192.0.2.250"]["role"] == "mining_pool"
        assert {"www-data", "root", "sysupdate"} <= attack_labels
        assert "uid=33" not in attack_labels
        assert "opsadmin" not in attack_labels

        edge_pairs = {(e["source"], e["target"]): e["label"] for e in attack_data["edges"]}
        assert ("ip-203.0.113.140", "host-WEB-01") in edge_pairs
        assert "Initial Access" in edge_pairs[("ip-203.0.113.140", "host-WEB-01")]
        assert ("host-WEB-01", "ip-198.51.100.201") in edge_pairs
        assert ("host-WEB-01", "ip-192.0.2.250") in edge_pairs
        assert ("host-WEB-01", "ip-203.0.113.140") in edge_pairs
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


def test_attack_path_only_full_compromise_roles_and_uid_preservation():
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
    graph = build_attack_graph(events, attack_path_only=True, findings=findings)

    labels = {n["label"] for n in graph["nodes"]}
    assert {"WEB-01", "203.0.113.140", "198.51.100.201", "192.0.2.250", "www-data", "root", "sysupdate"} <= labels
    assert "10.40.1.15" not in labels
    assert "uid=33" not in labels
    assert "opsadmin" not in labels

    by_label = {n["label"]: n for n in graph["nodes"]}
    assert "10.40.1.15" in ((by_label["WEB-01"].get("details") or {}).get("aliases") or [])
    assert by_label["198.51.100.201"]["role"] == "payload_host"
    assert by_label["192.0.2.250"]["role"] == "mining_pool"
    for f in findings:
        srcs = set(f.get("source_ips") or [])
        if f.get("src_ip"):
            srcs.add(str(f["src_ip"]))
        assert "10.40.1.15" not in srcs, f"Victim alias IP listed as source in finding: {f.get('rule_id')}"

    edge_pairs = {(e["source"], e["target"]): e["label"] for e in graph["edges"]}
    for required_edge in (
        ("ip-203.0.113.140", "host-WEB-01"),
        ("host-WEB-01", "ip-198.51.100.201"),
        ("host-WEB-01", "ip-192.0.2.250"),
        ("host-WEB-01", "ip-203.0.113.140"),
    ):
        assert required_edge in edge_pairs, f"Missing required edge: {required_edge}"

    # An unmapped uid without sudo/auth evidence must remain uid=999
    unmapped_uid_graph = build_attack_graph(
        [
            {
                "id": "u-1",
                "timestamp": "2026-07-22T02:00:00Z",
                "event_type": "auditd",
                "details": {"host": "WEB-01", "user": "uid=999", "command_line": "id"},
                "severity": "high",
                "is_attack_path": True,
            }
        ],
        attack_path_only=True,
    )
    assert "uid=999" in {n["label"] for n in unmapped_uid_graph["nodes"]}


def test_alias_map_normalizes_netflow_pcap_waf_and_merges_graph_node():
    raw_records = [
        {
            "timestamp": "2026-07-15T00:00:00Z",
            "event_type": "vuln_scan",
            "host": "APP-02",
            "extra": {"host_ip": "10.99.2.25", "cve": "CVE-2024-0001"},
        },
        {
            "timestamp": "2026-07-22T01:05:00Z",
            "event_type": "netflow",
            "source": "csv",
            "source_file": "07_netflow_export.csv",
            "src_ip": "10.99.2.25",
            "dst_ip": "198.51.100.77",
            "dst_port": 4444,
            "protocol": "TCP",
            "bytes": 4096,
        },
        {
            "timestamp": "2026-07-22T01:06:00Z",
            "event_type": "network_connection",
            "source": "pcap",
            "src_ip": "203.0.113.88",
            "dst_ip": "10.99.2.25",
            "dst_port": 443,
            "protocol": "TCP",
        },
        {
            "timestamp": "2026-07-22T01:07:00Z",
            "event_type": "edr_alert",
            "source": "SyntheticWAF",
            "src_ip": "203.0.113.88",
            "uri": "/login?id=1 OR 1=1",
            "rule": "SQL Injection Attack",
            "mitre_technique": "T1190",
        },
    ]
    normalized = normalize_records(raw_records)
    by_type = {rec["event_type"]: rec for rec in normalized}

    assert by_type["netflow"]["details"]["host"] == "APP-02"
    assert by_type["netflow"]["details"]["src_ip"] == "10.99.2.25"
    assert by_type["netflow"]["details"]["dst_ip"] == "198.51.100.77"
    assert by_type["network_connection"]["details"]["host"] == "APP-02"
    assert by_type["network_connection"]["details"]["src_ip"] == "203.0.113.88"
    assert by_type["network_connection"]["details"]["dst_ip"] == "10.99.2.25"
    assert by_type["edr_alert"]["details"]["host"] == "unknown_host"
    assert by_type["edr_alert"]["details"]["src_ip"] == "203.0.113.88"

    for i, rec in enumerate(normalized):
        rec["id"] = f"evt-{i}"

    findings = execute_detections_on_events(normalized, uuid.uuid4())
    graph = build_attack_graph(normalized, attack_path_only=False, findings=findings)

    node_labels = {n["label"] for n in graph["nodes"]}
    assert "APP-02" in node_labels
    assert "10.99.2.25" not in node_labels
    host_nodes = [n for n in graph["nodes"] if n["label"] == "APP-02"]
    assert len(host_nodes) == 1
    assert "10.99.2.25" in ((host_nodes[0].get("details") or {}).get("aliases") or [])
