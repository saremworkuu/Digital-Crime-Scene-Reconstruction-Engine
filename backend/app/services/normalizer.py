import re
from datetime import datetime, timezone
from typing import Any


def normalize_timestamp(record: dict[str, Any]) -> str | None:
    """
    Convert a record's timestamp to UTC in this format:
    YYYY-MM-DDTHH:MM:SSZ
    """
    # PCAP records use Unix timestamps.
    value = record.get("first_timestamp")

    if value is not None:
        try:
            timestamp = datetime.fromtimestamp(
                float(value), tz=timezone.utc
            )
            return timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError, OverflowError, OSError):
            pass

    # Other parsers may use a timestamp string.
    value = record.get("timestamp")

    if value is None or value == "":
        return None

    try:
        if isinstance(value, (int, float)):
            timestamp = datetime.fromtimestamp(
                float(value), tz=timezone.utc
            )
        else:
            text = str(value).strip()

            # Handle Linux syslog timestamps: "Oct 14 08:30:00"
            if re.fullmatch(
                r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
                text,
            ):
                current_year = datetime.now(timezone.utc).year
                timestamp = datetime.strptime(
                    f"{current_year} {text}",
                    "%Y %b %d %H:%M:%S",
                ).replace(tzinfo=timezone.utc)
            else:
                timestamp = datetime.fromisoformat(
                    text.replace("Z", "+00:00")
                )

                # Treat timestamps without timezone information as UTC.
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)

                timestamp = timestamp.astimezone(timezone.utc)

        return timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

    except (TypeError, ValueError, OverflowError, OSError):
        return None


def normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    """
    Convert one parser record into the common DCSRE event format.
    Store source-specific fields inside the details dictionary.
    """
    timestamp = normalize_timestamp(record)

    details = {
        key: value
        for key, value in record.items()
        if key not in {
            "timestamp",
            "first_timestamp",
            "event_type",
            "source",
        }
    }

    return {
        "timestamp": timestamp,
        "event_type": record.get("event_type", "unknown"),
        "source": record.get("source", "unknown"),
        "details": details,
    }



def normalize_records(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Normalize multiple records, skipping invalid timestamps."""
    normalized = []

    for record in records:
        event = normalize_record(record)

        # The Event database model requires a timestamp.
        if event["timestamp"] is None:
            continue

        normalized.append(event)

    return normalized
