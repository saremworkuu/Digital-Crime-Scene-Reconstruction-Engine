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
