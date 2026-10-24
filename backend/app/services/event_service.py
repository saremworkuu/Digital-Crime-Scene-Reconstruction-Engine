
import hashlib
import json
from datetime import datetime,timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.events import Event
from app.db.models.event_evidence import EventEvidence


def calculate_fingerprint(event_data: dict) -> str:
    """Create a stable SHA-256 fingerprint for an event with de-duplication on (source_file, source_record_id)."""
    details = event_data.get("details") or {}
    source_file = details.get("source_file") or ""
    source_record_id = details.get("source_record_id")

    if source_file and source_record_id is not None:
        identifying_data = {
            "source_file": str(source_file),
            "source_record_id": str(source_record_id),
        }
    else:
        identifying_data = {
            "timestamp": event_data.get("timestamp"),
            "event_type": event_data.get("event_type"),
            "source": event_data.get("source"),
            "host": details.get("host"),
            "raw": details.get("raw"),
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
                # Update details and event_type in place on re-parse
                existing_event.details = record["details"]
                existing_event.event_type = record["event_type"]
                existing_event.timestamp = timestamp
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
