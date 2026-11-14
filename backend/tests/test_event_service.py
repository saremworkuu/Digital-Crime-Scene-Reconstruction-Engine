
from datetime import datetime, timezone
from unittest.mock import MagicMock
from uuid import uuid4

from app.db.models.events import Event
from app.db.models.event_evidence import EventEvidence
from app.services.event_service import (
    calculate_fingerprint,
    save_normalized_events,
)


def sample_record():
    return {
        "timestamp": "2026-10-15T10:00:00Z",
        "event_type": "ssh_login",
        "source": "auth_log",
        "details": {"user": "alice", "result": "success"},
    }


def test_fingerprint_is_stable():
    record = sample_record()
    assert calculate_fingerprint(record) == calculate_fingerprint(record)


def test_fingerprint_ignores_dictionary_key_order():
    first = sample_record()
    second = {
        "details": {"result": "success", "user": "alice"},
        "source": "auth_log",
        "event_type": "ssh_login",
        "timestamp": "2026-10-15T10:00:00Z",
    }
    assert calculate_fingerprint(first) == calculate_fingerprint(second)



def test_save_normalized_event_creates_event_and_association():
    db = MagicMock()
    case_id = uuid4()
    evidence_id = uuid4()
    record = sample_record()

    # No matching event exists yet.
    db.execute.return_value.scalar_one_or_none.return_value = None
    db.get.return_value = None

    saved = save_normalized_events(db, case_id, evidence_id, [record])

    assert saved == 1

    # Inspect the actual objects passed to db.add().
    added_objects = [
        call.args[0]
        for call in db.add.call_args_list
    ]

    events = [
        obj for obj in added_objects
        if isinstance(obj, Event)
    ]
    associations = [
        obj for obj in added_objects
        if isinstance(obj, EventEvidence)
    ]

    assert len(events) == 1
    assert len(associations) == 1

    event = events[0]
    assert event.case_id == case_id
    assert event.evidence_id == evidence_id
    assert event.timestamp == datetime(
        2026, 10, 15, 10, 0, tzinfo=timezone.utc
    )
    assert event.event_type == "ssh_login"
    assert event.source == "auth_log"
    # A4 fix: details now includes ingested_at — use superset check
    expected_core = {"user": "alice", "result": "success"}
    assert expected_core.items() <= event.details.items(), \
        f"Core details missing from event.details: {event.details}"
    assert event.fingerprint == calculate_fingerprint({
        "timestamp": "2026-10-15T10:00:00+00:00",
        "event_type": "ssh_login",
        "source": "auth_log",
        "details": {"user": "alice", "result": "success"},
    })

    association = associations[0]
    assert association.event_id == event.id
    assert association.evidence_id == evidence_id


def test_duplicate_event_reuses_event_and_links_second_evidence():
    db = MagicMock()
    case_id = uuid4()
    first_evidence_id = uuid4()
    second_evidence_id = uuid4()
    existing_event_id = uuid4()

    record = sample_record()

    # Simulate an event already found in the first evidence file.
    existing_event = Event(
        id=existing_event_id,
        case_id=case_id,
        evidence_id=first_evidence_id,
        timestamp=datetime(
            2026, 10, 15, 10, 0, tzinfo=timezone.utc
        ),
        event_type="ssh_login",
        source="auth_log",
        details={"user": "alice", "result": "success"},
        fingerprint=calculate_fingerprint({
            "timestamp": "2026-10-15T10:00:00+00:00",
            "event_type": "ssh_login",
            "source": "auth_log",
            "details": {"user": "alice", "result": "success"},
        }),
    )

    db.execute.return_value.scalar_one_or_none.return_value = existing_event

    # The second evidence association does not exist yet.
    db.get.return_value = None

    saved = save_normalized_events(
        db=db,
        case_id=case_id,
        evidence_id=second_evidence_id,
        records=[record],
    )

    assert saved == 1

    added_objects = [
        call.args[0]
        for call in db.add.call_args_list
    ]

    # A duplicate must not create another Event.
    assert not any(
        isinstance(obj, Event)
        for obj in added_objects
    )

    # It must associate the existing event with the second file.
    associations = [
        obj for obj in added_objects
        if isinstance(obj, EventEvidence)
    ]

    assert len(associations) == 1
    assert associations[0].event_id == existing_event_id
    assert associations[0].evidence_id == second_evidence_id
    
if __name__ == "__main__":
    test_fingerprint_is_stable()
    test_fingerprint_ignores_dictionary_key_order()
    test_save_normalized_event_creates_event_and_association()
    test_duplicate_event_reuses_event_and_links_second_evidence()
    print("All event service tests passed!")
