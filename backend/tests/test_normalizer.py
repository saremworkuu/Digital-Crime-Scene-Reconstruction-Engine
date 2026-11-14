
from app.services.normalizer import (
    normalize_record,
    normalize_records,
    normalize_timestamp,
)


def test_pcap_unix_timestamp():
    pcap_record = {
        "event_type": "network_connection",
        "source": "pcap",
        "first_timestamp": 1000.0,
        "last_timestamp": 1002.0,
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "protocol": "TCP",
        "packets": 2,
        "bytes": 120,
    }

    event = normalize_record(pcap_record)

    assert event["timestamp"] == "1970-01-01T00:16:40Z"
    assert event["event_type"] == "network_connection"
    assert event["source"] == "pcap"
    assert event["details"]["last_timestamp"] == 1002.0
    assert event["details"]["source_ip"] == "192.168.1.10"


def test_iso_timestamp():
    assert normalize_timestamp({
        "timestamp": "2026-10-15T10:30:00Z"
    }) == "2026-10-15T10:30:00Z"


def test_timezone_offset_converts_to_utc():
    assert normalize_timestamp({
        "timestamp": "2026-10-15T13:30:00+03:00"
    }) == "2026-10-15T10:30:00Z"


def test_invalid_timestamp():
    assert normalize_timestamp({
        "timestamp": "not-a-timestamp"
    }) is None


def test_missing_timestamps_are_skipped():
    records = [
        {
            "event_type": "login",
            "source": "linux_auth",
            "timestamp": "2026-10-15T10:30:00Z",
            "user": "admin",
        },
        {
            "event_type": "unknown",
            "source": "test",
        },
    ]

    normalized = normalize_records(records)

    assert len(normalized) == 1
    assert normalized[0]["details"]["user"] == "admin"


def test_linux_syslog_timestamp():
    timestamp = normalize_timestamp({
        "timestamp": "Oct 14 08:30:00"
    })

    assert timestamp is not None
    assert timestamp.endswith("T08:30:00Z")
