"""Shared deterministic event ordering helpers independent of ingestion or DB UUID order."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Iterable, TypeVar

T = TypeVar("T")


def _extract_details(ev: Any) -> dict[str, Any]:
    if isinstance(ev, dict):
        details = ev.get("details")
        return details if isinstance(details, dict) else {}
    details = getattr(ev, "details", None)
    return details if isinstance(details, dict) else {}


def _get_field(ev: Any, details: dict[str, Any], name: str, default: Any = None) -> Any:
    if isinstance(ev, dict):
        val = ev.get(name)
        if val not in (None, ""):
            return val
    else:
        val = getattr(ev, name, None)
        if val not in (None, ""):
            return val
    val = details.get(name)
    if val not in (None, ""):
        return val
    extra = details.get("extra")
    if isinstance(extra, dict):
        val = extra.get(name)
        if val not in (None, ""):
            return val
    return default


def parse_utc_timestamp_tuple(ts_value: Any) -> tuple[int, int, int, int, int, int, int]:
    """Return a UTC (year, month, day, hour, minute, second, microsecond) sort key."""
    if ts_value is None or ts_value == "":
        return (0, 0, 0, 0, 0, 0, 0)
    try:
        if isinstance(ts_value, datetime):
            dt = ts_value
        else:
            raw = str(ts_value).strip()
            if not raw:
                return (0, 0, 0, 0, 0, 0, 0)
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond)
    except (ValueError, TypeError, OverflowError):
        return (0, 0, 0, 0, 0, 0, 0)


def _normalize_source_file(ev: Any, details: dict[str, Any]) -> str:
    raw_source = _get_field(ev, details, "source_file")
    if raw_source:
        return PurePosixPath(str(raw_source).replace("\\", "/")).name.casefold()
    src = _get_field(ev, details, "source") or _get_field(ev, details, "source_type") or ""
    return str(src).strip().casefold()


def _extract_record_index_key(ev: Any, details: dict[str, Any]) -> tuple[int, int, str]:
    """Extract a stable per-file record/line/packet order key."""
    candidate = None
    for key in (
        "source_record_id",
        "record_id",
        "event_record_id",
        "line_number",
        "line_no",
        "record_number",
        "packet_number",
    ):
        val = _get_field(ev, details, key)
        if val not in (None, ""):
            candidate = val
            break

    if candidate is None:
        return (2, 0, "")

    if isinstance(candidate, bool):
        return (1, int(candidate), str(candidate))
    if isinstance(candidate, int):
        return (0, candidate, "")
    text = str(candidate).strip()
    try:
        return (0, int(text), "")
    except ValueError:
        return (1, 0, text)


def _content_tiebreak_digest(
    ev: Any,
    details: dict[str, Any],
    ts_tuple: tuple[int, int, int, int, int, int, int],
    source_file: str,
    event_type: str,
    action: str,
) -> str:
    fp = _get_field(ev, details, "fingerprint")
    if fp:
        return str(fp)
    payload = {
        "ts": ts_tuple,
        "source_file": source_file,
        "event_type": event_type,
        "action": action,
        "host": str(_get_field(ev, details, "host", "") or ""),
        "user": str(_get_field(ev, details, "user") or _get_field(ev, details, "username") or ""),
        "src_ip": str(_get_field(ev, details, "src_ip") or _get_field(ev, details, "source_ip") or ""),
        "dst_ip": str(_get_field(ev, details, "dst_ip") or _get_field(ev, details, "destination_ip") or ""),
        "raw": str(_get_field(ev, details, "raw") or _get_field(ev, details, "raw_message") or ""),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def event_sort_key(ev: Any) -> tuple:
    """Deterministic total order key based solely on event content, never ingestion order or UUID."""
    details = _extract_details(ev)
    ts_val = ev.get("timestamp") if isinstance(ev, dict) else getattr(ev, "timestamp", None)
    if ts_val in (None, ""):
        ts_val = details.get("timestamp")
    ts_tuple = parse_utc_timestamp_tuple(ts_val)
    source_file = _normalize_source_file(ev, details)
    record_key = _extract_record_index_key(ev, details)
    event_type = str(_get_field(ev, details, "event_type", "") or "").casefold()
    action = str(
        _get_field(ev, details, "action") or _get_field(ev, details, "message") or ""
    ).strip().casefold()
    digest = _content_tiebreak_digest(ev, details, ts_tuple, source_file, event_type, action)
    return (ts_tuple, source_file, record_key, event_type, action, digest)


def sort_events(events: Iterable[T]) -> list[T]:
    """Return events sorted by deterministic content-based total order."""
    return sorted(events, key=event_sort_key)
