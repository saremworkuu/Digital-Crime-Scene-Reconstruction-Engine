
import hashlib
import json
from datetime import datetime,timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.events import Event
from app.db.models.event_evidence import EventEvidence


def calculate_fingerprint(event_data: dict) -> str:
    """Create a stable SHA-256 fingerprint for an event."""
    identifying_data = {
        "timestamp": event_data["timestamp"],
        "event_type": event_data["event_type"],
        "source": event_data["source"],
        "details": event_data["details"],
    }

    canonical_data = json.dumps(
        identifying_data,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    return hashlib.sha256(canonical_data.encode("utf-8")).hexdigest()


def save_normalized_events(
    db: Session,
    case_id,
    evidence_id,
    records: list[dict],
) -> int:
    """Save normalized records and associate them with their evidence."""
    saved_count = 0

    for record in records:
        try:
            timestamp_value = record.get("timestamp")
            if not timestamp_value:
                continue

            timestamp = datetime.fromisoformat(
                timestamp_value.replace("Z", "+00:00")
            )

            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)

            timestamp = timestamp.astimezone(timezone.utc)

            event_data = {
                "timestamp": timestamp.isoformat(),
                "event_type": record["event_type"],
                "source": record["source"],
                "details": record["details"],
            }
            fingerprint = calculate_fingerprint(event_data)

            existing_event = db.execute(
                select(Event).where(
                    Event.case_id == case_id,
                    Event.fingerprint == fingerprint,
                )
            ).scalar_one_or_none()

            if existing_event is not None:
                event_id = existing_event.id
            else:
                event = Event(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    timestamp=timestamp,
                    event_type=record["event_type"],
                    source=record["source"],
                    details=record["details"],
                    fingerprint=fingerprint,
                )
                db.add(event)
                db.flush()
                event_id = event.id

            association = db.get(
                EventEvidence,
                {
                    "event_id": event_id,
                    "evidence_id": evidence_id,
                },
            )

            if association is None:
                db.add(
                    EventEvidence(
                        event_id=event_id,
                        evidence_id=evidence_id,
                    )
                )

            saved_count += 1

        except (KeyError, TypeError, ValueError, OverflowError):
            # Skip malformed records without abandoning the rest.
            continue

    return saved_count
