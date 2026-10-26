from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.services.detection import (
    detect_macro_attachment_delivery,
    detect_periodic_beaconing,
    detect_repeated_failed_logins,
    detect_smb_lateral_movement,
)
from app.services.entity_classification import is_internal_ip
from app.services.report_fixes import unique_users
from app.services.report import generate_forensic_report_data
from app.services.graph import build_attack_graph
from app.services.report import _format_timeline_time
from app.services.report_fixes import merge_timeline
from app.schemas.events import EventResponse
from uuid import uuid4


def _event(event_id, seconds, event_type="network_connection", **details):
    return SimpleNamespace(
        id=event_id,
        timestamp=datetime(2026, 9, 3, tzinfo=timezone.utc) + timedelta(seconds=seconds),
        event_type=event_type,
        details=details,
    )


def test_windows_failed_logons_do_not_create_ssh_bruteforce():
    events = [_event(str(i), i, event_type="4625", message="failed logon", source_ip="198.51.100.20") for i in range(3)]
    assert detect_repeated_failed_logins(events) == []


def test_ssh_bruteforce_requires_and_records_ssh_events():
    events = [_event(str(i), i, event_type="ssh_failed", message="SSH authentication failure", source_ip="198.51.100.20") for i in range(3)]
    findings = detect_repeated_failed_logins(events)
    assert len(findings) == 1
    assert findings[0]["matching_event_ids"] == ["0", "1", "2"]


def test_internal_and_external_classification_and_user_deduplication():
    assert is_internal_ip("10.2.3.4")
    assert not is_internal_ip("198.51.100.66")
    assert unique_users([r"ACME\mlee", "mlee@acme", "MLEE"]) == [r"ACME\mlee"]


def test_detects_delivered_macro_attachment():
    event = _event("mail-1", 0, event_type="email_delivery", action="message delivered", recipient="ACME\\mlee", attachment="invoice.docm")
    finding, = detect_macro_attachment_delivery([event])
    assert finding["mitre_technique"] == "T1566.001"
    assert finding["mitre_tactic"] == "Initial Access"
    assert finding["matching_event_ids"] == ["mail-1"]


def test_detects_three_smb_targets_within_one_minute():
    events = [_event(f"smb-{i}", i * 20, event_type="network_connection", source_host="WS-01", target_host=f"SRV-{i}", destination_port=445) for i in range(3)]
    finding, = detect_smb_lateral_movement(events)
    assert finding["mitre_technique"] == "T1021.002"
    assert len(finding["rule_information"]["target_hosts"]) == 3


def test_detects_regular_external_beaconing():
    events = [_event(f"net-{i}", i * 60, destination_ip="203.0.113.8", destination_port=443) for i in range(4)]
    finding, = detect_periodic_beaconing(events)
    assert finding["mitre_technique"] == "T1071"
    assert finding["matching_event_ids"] == ["net-0", "net-1", "net-2", "net-3"]


def test_report_excludes_unmatched_and_foreign_event_findings_and_uses_event_time():
    event = {"id": "case-event", "timestamp": "2026-09-03T07:41:27Z", "host": "WS-01", "user": "ACME\\mlee", "action": "Process execution", "source_file": "sysmon.xml"}
    findings = [
        {"id": "valid", "rule_id": "r1", "rule_name": "Execution", "matching_event_ids": ["case-event"], "first_seen": "2026-10-24T14:18:06Z", "mitre_technique": "T1059", "mitre_tactic": "Execution"},
        {"id": "empty", "rule_id": "r2", "rule_name": "No event", "matching_event_ids": []},
        {"id": "foreign", "rule_id": "r3", "rule_name": "Other case", "matching_event_ids": ["another-case-event"]},
    ]
    report = generate_forensic_report_data({"id": "case-1", "name": "Case"}, [], [event], findings, version="1.0")
    assert [item["id"] for item in report["mitre_coverage"]] == ["valid"]
    assert report["mitre_coverage"][0]["first_seen"] == event["timestamp"]
    assert report["attack_timeline_summary"][0]["timestamp"] == event["timestamp"]


def test_report_content_hash_is_repeatable_for_same_data():
    args = ({"id": "case-1", "name": "Case"}, [], [], [])
    first = generate_forensic_report_data(*args, version="1.0")
    second = generate_forensic_report_data(*args, version="1.0")
    assert first["report_hash"] == second["report_hash"]


def test_report_adversary_infrastructure_contains_addresses_not_domains():
    event = {"id": "net-1", "timestamp": "2026-09-03T07:41:30Z", "event_type": "network_connection",
             "host": "WS-01", "src_ip": "10.0.0.2", "dst_ip": "203.0.113.9", "action": "connection"}
    finding = {"id": "finding-1", "rule_id": "beacon", "rule_name": "External Beacon",
               "matching_event_ids": ["net-1"], "first_seen": event["timestamp"],
               "mitre_technique": "T1071", "mitre_tactic": "Command and Control",
               "actor": "203.0.113.9", "actor_role": "adversary_infrastructure",
               "rule_information": {"domains": ["updates.example"]}}
    report = generate_forensic_report_data({"id": "case-1", "name": "Case"}, [], [event], [finding], version="1.0")
    assert "203.0.113.9" in report["compromised_assets"]["adversary_infrastructure"]
    assert "updates.example" not in report["compromised_assets"]["adversary_infrastructure"]


def test_report_qualifies_attachment_delivery_without_claiming_malicious_execution():
    event = {"id": "mail-1", "timestamp": "2026-09-03T02:14:10", "event_type": "email_delivery",
             "host": "mailgw", "user": "mlee", "action": "delivered Resume_Candidate.docm",
             "timestamp_timezone_known": False}
    finding = {"id": "mail-finding", "rule_id": "mail_macro_attachment", "rule_name": "Macro-Enabled or Script Archive Delivered",
               "matching_event_ids": ["mail-1"], "first_seen": event["timestamp"], "mitre_technique": "T1566.001",
               "mitre_tactic": "Initial Access", "severity": "high", "description": "Delivery observed; execution is not established."}
    report = generate_forensic_report_data({"id": "case-1", "name": "Case"}, [], [event], [finding], version="1.0")
    assert "malicious content and execution are not established" in report["executive_summary"]
    assert "Likely initial access" not in report["executive_summary"]


def test_event_response_extracts_timestamped_text_host_and_explicit_timezone():
    response = EventResponse.model_validate({
        "id": uuid4(), "case_id": uuid4(), "evidence_id": uuid4(),
        "timestamp": "2026-09-03T10:12:38Z", "event_type": "text_log", "source": "fileserver",
        "details": {"raw_message": "2026-09-03T10:12:38Z SRV-FS-02 FSAUDIT user=admin_svc rename", "user": "admin_svc", "extra": {"TargetDomainName": "ACME"}},
    })
    assert response.host == "SRV-FS-02"
    assert response.user == r"ACME\admin_svc"
    assert response.timestamp_timezone_known is True


def test_event_response_marks_syslog_timezone_as_unspecified():
    response = EventResponse.model_validate({
        "id": uuid4(), "case_id": uuid4(), "evidence_id": uuid4(),
        "timestamp": "2026-09-03T02:14:10Z", "event_type": "mail_log", "source": "mailgw",
        "details": {"host": "unknown_host", "host_inferred": True, "extra": {"raw_message": "Sep  3 02:14:10 mailgw postfix: from=<sender@example.invalid> to=<mlee@acme.example> status=delivered"}},
    })
    assert response.host == "mailgw"
    assert response.user == "mlee@acme.example"
    assert response.timestamp_timezone_known is False


def test_report_timeline_marks_unzoned_source_time():
    rows = merge_timeline([{"id": "mail-1", "timestamp": "2026-09-03T02:14:10", "host": "mailgw",
                            "user": "unknown", "action": "delivery", "source": "mailgw",
                            "timestamp_timezone_known": False}])
    rendered = _format_timeline_time(rows[0])
    assert rendered == "2026-09-03 02:14:10 (source timezone unspecified)"


def test_graph_merges_source_ip_to_workstation_and_deduplicates_domain_user():
    events = [
        {"id": "1", "timestamp": "2026-09-03T08:33:01Z", "event_type": "windows_event", "host": "DC-01", "user": "mlee",
         "details": {"WorkstationName": "WS-HR-12", "TargetDomainName": "ACME", "host": "DC-01"}, "src_ip": "10.20.1.12"},
        {"id": "2", "timestamp": "2026-09-03T08:33:02Z", "event_type": "windows_event", "host": "WS-HR-12", "user": r"ACME\mlee", "details": {}, "src_ip": "10.20.1.12"},
        {"id": "3", "timestamp": "2026-09-03T08:33:03Z", "event_type": "network_connection", "host": "WS-HR-12", "src_ip": "10.20.1.12", "dst_ip": "198.51.100.66", "details": {}},
    ]
    graph = build_attack_graph(events)
    labels = [node["label"] for node in graph["nodes"]]
    assert labels.count("WS-HR-12") == 1
    assert labels.count(r"ACME\mlee") == 1
    assert labels.count("198.51.100.66") == 1
    assert "host-198.51.100.66" not in {node["id"] for node in graph["nodes"]}
