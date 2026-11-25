import uuid
from pathlib import Path

from app.parsers.registry import get_parser
from app.services.correlation import MIN_CHAIN_CONFIDENCE, correlate_attack_chains
from app.services.normalizer import normalize_records


WEB_COMPROMISE_DIR = (
    Path(__file__).resolve().parents[1] / "test_evidence" / "web_server_compromise"
)


def test_correlation_respects_min_confidence_threshold_on_sample_case():
    assert MIN_CHAIN_CONFIDENCE == 0.70

    events = []
    for fname in ("01_apache_access.log", "02_auth.log", "03_auditd.log"):
        fpath = WEB_COMPROMISE_DIR / fname
        assert fpath.is_file(), f"Missing fixture: {fpath}"
        records = get_parser(fpath, original_filename=fname).parse(fpath, original_filename=fname)
        for rec in normalize_records(records, default_filename=fname):
            rec["id"] = str(uuid.uuid4())
            events.append(rec)

    chains = correlate_attack_chains(events, window_minutes=45)
    assert len(chains) >= 1
    assert all(chain["confidence_score"] >= MIN_CHAIN_CONFIDENCE for chain in chains)

    # A 2-event pair yields 0.5 + 2*0.08 = 0.66 (< MIN_CHAIN_CONFIDENCE) and must be excluded by default
    two_event_pair = [
        {
            "id": "low-1",
            "timestamp": "2026-07-22T01:00:00Z",
            "host": "WEB-01",
            "user": "opsadmin",
            "action": "login",
            "severity": "low",
            "is_attack_path": False,
        },
        {
            "id": "low-2",
            "timestamp": "2026-07-22T01:05:00Z",
            "host": "WEB-01",
            "user": "opsadmin",
            "action": "command",
            "severity": "low",
            "is_attack_path": False,
        },
    ]
    assert correlate_attack_chains(two_event_pair) == []
    assert len(correlate_attack_chains(two_event_pair, min_confidence=0.60)) == 1
