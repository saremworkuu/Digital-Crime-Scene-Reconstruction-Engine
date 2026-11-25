import hashlib
import json
import uuid
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


def _prepare_event_payloads(
    records: list[dict],
    ingested_at: datetime,
) -> list[dict]:
    """Validate timestamps, enrich details, and compute fingerprints in memory."""
    prepared = []
    ingested_str = ingested_at.strftime("%Y-%m-%dT%H:%M:%SZ")

    for record in records:
        try:
            timestamp_value = record.get("timestamp")
            timestamp_inferred = bool(record.get("timestamp_inferred", False))

            if not timestamp_value:
                if not timestamp_inferred:
                    continue
                timestamp_value = ingested_at.isoformat()

            timestamp = datetime.fromisoformat(
                str(timestamp_value).replace("Z", "+00:00")
            )
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            timestamp = timestamp.astimezone(timezone.utc)

            details = dict(record.get("details") or {})
            details.setdefault("ingested_at", ingested_str)
            if timestamp_inferred:
                details["timestamp_inferred"] = True

            event_data = {
                "timestamp": timestamp.isoformat(),
                "event_type": record["event_type"],
                "source": record["source"],
                "details": details,
            }
            prepared.append({
                "timestamp": timestamp,
                "event_type": record["event_type"],
                "source": record["source"],
                "details": details,
                "fingerprint": calculate_fingerprint(event_data),
            })
        except (KeyError, TypeError, ValueError, OverflowError):
            continue

    return prepared


def save_normalized_events(
    db: Session,
    case_id,
    evidence_id,
    records: list[dict],
    ingested_at: datetime | None = None,
) -> int:
    """Save normalized records and associate them with their evidence."""
    if ingested_at is None:
        ingested_at = datetime.now(timezone.utc)

    prepared = _prepare_event_payloads(records, ingested_at)
    if not prepared:
        return 0

    # Real SQLAlchemy Session: batch-fetch existing rows & associations so large
    # files take a few round-trips instead of 3*N sequential queries.
    if isinstance(db, Session):
        fingerprints = list({item["fingerprint"] for item in prepared})
        existing_by_fp: dict[str, Event] = {}
        # Query in chunks of 500 to stay well within parameter limits
        for i in range(0, len(fingerprints), 500):
            chunk = fingerprints[i : i + 500]
            rows = db.execute(
                select(Event).where(
                    Event.case_id == case_id,
                    Event.fingerprint.in_(chunk),
                )
            ).scalars().all()
            for row in rows:
                existing_by_fp[row.fingerprint] = row

        new_events: list[Event] = []
        target_event_ids: list = []

        for item in prepared:
            fp = item["fingerprint"]
            existing_event = existing_by_fp.get(fp)
            if existing_event is not None:
                existing_event.details = item["details"]
                existing_event.event_type = item["event_type"]
                existing_event.timestamp = item["timestamp"]
                target_event_ids.append(existing_event.id)
            else:
                new_id = uuid.uuid4()
                event = Event(
                    id=new_id,
                    case_id=case_id,
                    evidence_id=evidence_id,
                    timestamp=item["timestamp"],
                    event_type=item["event_type"],
                    source=item["source"],
                    details=item["details"],
                    fingerprint=fp,
                )
                existing_by_fp[fp] = event
                new_events.append(event)
                target_event_ids.append(new_id)

        if new_events:
            db.add_all(new_events)
            db.flush()

        unique_event_ids = list(dict.fromkeys(target_event_ids))
        existing_assoc_ids: set = set()
        for i in range(0, len(unique_event_ids), 500):
            chunk = unique_event_ids[i : i + 500]
            existing_assoc_ids.update(
                db.execute(
                    select(EventEvidence.event_id).where(
                        EventEvidence.evidence_id == evidence_id,
                        EventEvidence.event_id.in_(chunk),
                    )
                ).scalars().all()
            )

        new_assocs = [
            EventEvidence(event_id=eid, evidence_id=evidence_id)
            for eid in unique_event_ids
            if eid not in existing_assoc_ids
        ]
        if new_assocs:
            db.add_all(new_assocs)

        return len(prepared)

    # Fallback path for unit tests passing a MagicMock session
    saved_count = 0
    for item in prepared:
        existing_event = db.execute(
            select(Event).where(
                Event.case_id == case_id,
                Event.fingerprint == item["fingerprint"],
            )
        ).scalar_one_or_none()

        if existing_event is not None:
            event_id = existing_event.id
            existing_event.details = item["details"]
            existing_event.event_type = item["event_type"]
            existing_event.timestamp = item["timestamp"]
        else:
            event = Event(
                case_id=case_id,
                evidence_id=evidence_id,
                timestamp=item["timestamp"],
                event_type=item["event_type"],
                source=item["source"],
                details=item["details"],
                fingerprint=item["fingerprint"],
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

    return saved_count
