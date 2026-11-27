import uuid
from pathlib import Path

from app.parsers.registry import get_parser
from app.services.correlation import MIN_CHAIN_CONFIDENCE, correlate_attack_chains
from app.services.detection_engine import execute_detections_on_events
from app.services.normalizer import normalize_records


WEB_COMPROMISE_DIR = (
    Path(__file__).resolve().parents[1] / "test_evidence" / "web_server_compromise"
)


def _load_sample_events():
    events = []
    for path in sorted(WEB_COMPROMISE_DIR.iterdir()):
        if not path.is_file():
            continue
        records = get_parser(path, original_filename=path.name).parse(path, original_filename=path.name)
        for rec in normalize_records(records, default_filename=path.name):
            rec["id"] = str(uuid.uuid4())
            events.append(rec)
    return events


def test_correlation_reconstructs_single_detection_backed_chain_without_benign_traffic():
    assert MIN_CHAIN_CONFIDENCE == 0.70

    events = _load_sample_events()
    detections = execute_detections_on_events(events, uuid.uuid4())
    chains = correlate_attack_chains(events, window_minutes=45, detections=detections)

    assert len(chains) == 1
    chain = chains[0]
    assert chain["name"] == "203.0.113.140 -> WEB-01: Reconnaissance -> Defense Evasion"
    assert chain["confidence_score"] == 0.95
    assert chain["confidence_score"] >= MIN_CHAIN_CONFIDENCE

    # Ordered by event time
    timestamps = [ev["timestamp"] for ev in chain["events"]]
    assert timestamps == sorted(timestamps)

    # No benign 192.0.2.x customer traffic and no context/unlinked metric noise
    assert not any(str(ev.get("src_ip") or "").startswith("192.0.2.") for ev in chain["events"])
    assert not any(ev.get("event_type") == "vuln_scan" or ev.get("category") == "context" for ev in chain["events"])

    # Unlinked/benign-only events must not form a chain
    assert correlate_attack_chains(events, detections=[]) == []


def test_correlation_respects_false_positives_tactic_minimum_and_confidence_filter():
    events = [
        {"id": "e1", "timestamp": "2026-07-22T01:00:00Z", "host": "APP-01", "src_ip": "198.51.100.10", "severity": "medium", "action": "scan"},
        {"id": "e2", "timestamp": "2026-07-22T01:05:00Z", "host": "APP-01", "src_ip": "198.51.100.10", "severity": "high", "action": "exploit"},
        {"id": "e3", "timestamp": "2026-07-22T01:10:00Z", "host": "APP-01", "src_ip": "198.51.100.10", "severity": "high", "action": "exec"},
        {"id": "e4", "timestamp": "2026-07-22T01:15:00Z", "host": "APP-01", "src_ip": "198.51.100.10", "severity": "high", "action": "persist"},
        {"id": "benign-host", "timestamp": "2026-07-22T01:08:00Z", "host": "APP-01", "src_ip": "192.0.2.99", "severity": "low", "action": "GET /health"},
        {"id": "metric-unlinked", "timestamp": "2026-07-22T01:09:00Z", "host": "APP-01", "event_type": "metric", "severity": "low", "action": "CPU 20%"},
    ]
    three_tactic_dets = [
        {"mitre_tactic": "Reconnaissance", "target_host": "APP-01", "matching_event_ids": ["e1"], "false_positive": False},
        {"mitre_tactic": "Initial Access", "target_host": "APP-01", "matching_event_ids": ["e2"], "false_positive": False},
        {"mitre_tactic": "Execution", "target_host": "APP-01", "matching_event_ids": ["e3"], "false_positive": False},
        {"mitre_tactic": "Persistence", "target_host": "APP-01", "matching_event_ids": ["e4"], "false_positive": True},
    ]

    # 3 non-FP tactics => confidence 0.40 + 0.24 = 0.64 (< 0.70 default)
    assert correlate_attack_chains(events, detections=three_tactic_dets) == []
    low_thresh = correlate_attack_chains(events, min_confidence=0.60, detections=three_tactic_dets)
    assert len(low_thresh) == 1
    assert low_thresh[0]["confidence_score"] == 0.64
    chained_ids = {ev["id"] for ev in low_thresh[0]["events"]}
    assert "benign-host" not in chained_ids
    assert "metric-unlinked" not in chained_ids
    assert "e4" not in chained_ids

    # 4 non-FP tactics => confidence 0.40 + 0.32 = 0.72 (>= 0.70 default)
    four_tactic_dets = [dict(d, false_positive=False) for d in three_tactic_dets]
    chains = correlate_attack_chains(events, detections=four_tactic_dets)
    assert len(chains) == 1
    assert chains[0]["confidence_score"] == 0.72
    assert chains[0]["name"] == "198.51.100.10 -> APP-01: Reconnaissance -> Persistence"
