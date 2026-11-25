import uuid
from pathlib import Path

from app.parsers.registry import get_parser
from app.services.detection_engine import execute_detections_on_events
from app.services.normalizer import normalize_records


WEB_COMPROMISE_DIR = (
    Path(__file__).resolve().parents[1] / "test_evidence" / "web_server_compromise"
)


def _load_normalized(filename: str) -> list[dict]:
    fpath = WEB_COMPROMISE_DIR / filename
    assert fpath.is_file(), f"Missing fixture: {fpath}"
    records = get_parser(fpath, original_filename=filename).parse(fpath, original_filename=filename)
    return normalize_records(records, default_filename=filename)


def test_improved_event_titles_under_160_chars_and_keep_detections():
    apache = _load_normalized("01_apache_access.log")
    assert all(r["event_type"] == "web_access" for r in apache)
    assert all(len(r["details"]["action"]) < 160 for r in apache)
    assert all("web_access on" not in r["details"]["action"] for r in apache)
    sqlmap_title = next(r["details"]["action"] for r in apache if "sqlmap" in r["details"]["action"])
    assert sqlmap_title.startswith("GET /product.php?id=1")
    assert "(sqlmap/1.7.8)" in sqlmap_title

    waf = _load_normalized("04_waf_alerts.json")
    assert all(len(r["details"]["action"]) < 160 for r in waf)
    assert all(r["details"]["action"] != "logged_not_blocked" for r in waf)
    assert "[rule 942100] logged_not_blocked" in waf[0]["details"]["action"]
    assert waf[0]["details"]["action"].startswith("SQL Injection Attack Detected via libinjection")

    mysql = _load_normalized("05_mysql_general.log")
    assert [r["event_type"] for r in mysql] == ["db_query", "db_query", "db_query", "db_connect", "db_query"]
    assert all(len(r["details"]["action"]) < 160 for r in mysql)
    assert all("log_event" not in r["details"]["action"] for r in mysql)
    assert mysql[0]["details"]["action"].startswith("SELECT id,name,price FROM products WHERE id=1'")
    assert len(mysql[2]["details"]["action"]) == 100

    netflow = _load_normalized("07_netflow_export.csv")
    assert all(r["event_type"] == "network_connection" for r in netflow)
    assert all(len(r["details"]["action"]) < 160 for r in netflow)
    exfil_flow = next(r for r in netflow if r["details"].get("dst_ip") == "203.0.113.140" and r["details"].get("dst_port") == 22)
    assert exfil_flow["details"]["action"] == "TCP 10.40.1.15:55120 -> 203.0.113.140:22, 39.5 MB out"

    metrics = _load_normalized("08_system_metrics.csv")
    assert all(r["event_type"] == "metric" for r in metrics)
    assert all(len(r["details"]["action"]) < 160 for r in metrics)
    assert all("Metrics for" not in r["details"]["action"] for r in metrics)
    assert metrics[0]["details"]["action"] == "WEB-01 CPU 20% MEM 51%"

    # Confirm detections still fire across the sample case with the updated titles
    all_events = []
    for fname in (
        "01_apache_access.log",
        "02_auth.log",
        "03_auditd.log",
        "04_waf_alerts.json",
        "05_mysql_general.log",
        "07_netflow_export.csv",
        "08_system_metrics.csv",
    ):
        for r in _load_normalized(fname):
            r["id"] = str(uuid.uuid4())
            all_events.append(r)

    findings = execute_detections_on_events(all_events, uuid.uuid4())
    rule_ids = {f["rule_id"] for f in findings}
    assert {
        "rule-web-sql-injection",
        "rule-double-extension-upload",
        "rule-webshell-request",
        "rule-reverse-shell-pattern",
        "rule-miner-pool-ports",
    }.issubset(rule_ids)
