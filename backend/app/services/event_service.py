import hashlib
import json
from datetime import datetime, timezone

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
    ingested_at: datetime | None = None,
) -> int:
    """Save normalized records and associate them with their evidence.

    A4 fix:
    - ``timestamp`` on the Event row stores the real *event_time* parsed from
      the evidence file.
    - ``ingested_at`` (upload time) is stored in ``details['ingested_at']`` so
      it is always available in API responses without touching the DB schema.
    - Records whose parser could not determine a timestamp get
      ``details['timestamp_inferred'] = True``; they are **not** silently
      assigned the upload time.  They are stored with the ``evidence.uploaded_at``
      only when the parser itself explicitly requests it via
      ``record['timestamp_inferred'] = True``.
    """
    if ingested_at is None:
        ingested_at = datetime.now(timezone.utc)

    saved_count = 0

    for record in records:
        try:
            timestamp_value = record.get("timestamp")
            timestamp_inferred = bool(record.get("timestamp_inferred", False))

            if not timestamp_value:
                if not timestamp_inferred:
                    # No timestamp at all – skip the record (do NOT substitute
                    # upload time silently).  Store it only when the parser
                    # explicitly marks it as inferred.
                    continue
                # Parser flagged timestamp_inferred – use evidence ingestion
                # time as a last resort but keep the flag in details.
                timestamp_value = ingested_at.isoformat()

            timestamp = datetime.fromisoformat(
                str(timestamp_value).replace("Z", "+00:00")
            )

            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)

            timestamp = timestamp.astimezone(timezone.utc)

            # Embed ingested_at into details so every API response exposes it.
            details = dict(record.get("details") or {})
            details.setdefault("ingested_at", ingested_at.strftime("%Y-%m-%dT%H:%M:%SZ"))
            if timestamp_inferred:
                details["timestamp_inferred"] = True

            event_data = {
                "timestamp": timestamp.isoformat(),
                "event_type": record["event_type"],
                "source": record["source"],
                "details": details,
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
                existing_event.details = details
                existing_event.event_type = record["event_type"]
                existing_event.timestamp = timestamp
            else:
                event = Event(
                    case_id=case_id,
                    evidence_id=evidence_id,
                    timestamp=timestamp,
                    event_type=record["event_type"],
                    source=record["source"],
                    details=details,
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
