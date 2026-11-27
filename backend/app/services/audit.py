# Audit service

from datetime import datetime, timezone
import re
import uuid
from typing import TYPE_CHECKING, Any

from fastapi import Request
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from app.db.models.audit_log import AuditLog
    from app.db.models.user import User

_PARSER_NAME_MAP = {
    "authlogparser": "auth_log",
    "linux_auth": "auth_log",
    "auth_log": "auth_log",
    "auth": "auth_log",
    "webaccessparser": "web_access",
    "apacheaccessparser": "web_access",
    "web_server": "web_access",
    "web_access": "web_access",
    "apache_access": "web_access",
    "auditdparser": "auditd",
    "auditd": "auditd",
    "mysqlgenerallogparser": "mysql_general",
    "mysql_general": "mysql_general",
    "mysql": "mysql_general",
    "genericcsvjsonparser": "generic_csv_json",
    "generic_json_csv": "generic_csv_json",
    "generic_csv_json": "generic_csv_json",
    "generic": "generic_csv_json",
    "windowsevtxparser": "windows_evtx",
    "windows_evtx": "windows_evtx",
    "evtx": "windows_evtx",
    "vulnscanparser": "vuln_scan",
    "vuln_scan": "vuln_scan",
    "pcapparser": "pcap",
    "pcap_summary": "pcap",
    "pcap": "pcap",
    "pcapngparser": "pcapng",
    "pcapng": "pcapng",
    "logfileparser": "log_parser",
    "log_parser": "log_parser",
    "syslog": "log_parser",
    "textfileparser": "txt_parser",
    "txt_parser": "txt_parser",
    "text": "txt_parser",
}

_ACTION_MAP = {
    "EVIDENCE_UPLOADED": "evidence.uploaded",
    "EVIDENCE_PARSED": "evidence.parsed",
    "EVIDENCE_DOWNLOADED": "evidence.downloaded",
    "EVIDENCE_DELETED": "evidence.deleted",
    "EVIDENCE_DELETE": "evidence.deleted",
    "EVIDENCE_VERIFY": "evidence.verified",
    "EVIDENCE_VERIFIED": "evidence.verified",
    "CASE_CREATED": "case.created",
    "CASE_UPDATED": "case.updated",
    "CASE_STATUS_CHANGED": "case.status_changed",
    "CASE_STATUS_UPDATE": "case.status_changed",
    "CASE_DELETED": "case.deleted",
    "CASE_ASSIGNMENT": "case.assigned",
    "CASE_ASSIGNED": "case.assigned",
    "CASE_LEGAL_HOLD_SET": "case.legal_hold_set",
    "CASE_LEGAL_HOLD_REMOVED": "case.legal_hold_removed",
    "CASE_ARCHIVE": "case.archived",
    "CASE_UNARCHIVE": "case.unarchived",
    "REPORT_GENERATED": "report.generated",
    "REPORT_VIEWED": "report.viewed",
    "REPORT_DOWNLOADED": "report.downloaded",
    "SAVED_REPORT_DOWNLOADED": "report.downloaded",
    "REPORT_EXPORTED": "report.exported",
    "DETECTION_FP_TOGGLED": "detection.false_positive_toggled",
    "DETECTION_RULE_ADDED": "detection.rule_added",
    "TIMELINE_EXPORTED": "timeline.exported",
    "USER_REGISTERED": "user.registered",
    "USER_LOGIN": "user.login",
    "USER_LOGOUT": "user.logout",
    "USER_CREATE": "user.created",
    "USER_UPDATE": "user.updated",
    "USER_UPDATED": "user.updated",
    "USER_DELETE": "user.deleted",
    "USER_PASSWORD_RESET": "user.password_reset",
    "SESSION_TERMINATED": "session.terminated",
    "MESSAGE_STATUS_UPDATE": "message.status_updated",
    "MESSAGE_PRIORITY_UPDATE": "message.priority_updated",
    "MESSAGE_ASSIGNED": "message.assigned",
    "MESSAGE_REPLY_SENT": "message.reply_sent",
    "MESSAGE_MARK_SPAM": "message.marked_spam",
    "MESSAGE_SOFT_DELETE": "message.deleted",
    "SIGMA_RULE_CREATE": "sigma_rule.created",
    "SIGMA_RULE_UPDATE": "sigma_rule.updated",
    "SIGMA_RULE_ENABLE": "sigma_rule.enabled",
    "SIGMA_RULE_DISABLE": "sigma_rule.disabled",
    "SIGMA_RULE_DELETE": "sigma_rule.deleted",
    "SIGMA_RULES_IMPORTED": "sigma_rule.imported",
    "INGESTION_JOB_RETRY": "ingestion.retried",
    "SYSTEM_SETTINGS_UPDATE": "system.settings_updated",
    "DEMO_DATA_RESET": "system.demo_data_reset",
}

_REVERSE_ACTION_MAP: dict[str, set[str]] = {}
for _legacy, _canon in _ACTION_MAP.items():
    _REVERSE_ACTION_MAP.setdefault(_canon, set()).update({_canon, _legacy})


def utc_now() -> datetime:
    """Single UTC-aware timestamp helper for all audit operations."""
    return datetime.now(timezone.utc)


def normalize_audit_timestamp(value: datetime | str | None) -> datetime:
    """Normalize naive/aware datetimes or ISO strings to UTC-aware datetimes."""
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.min.replace(tzinfo=timezone.utc)


def format_audit_timestamp_iso(value: datetime | str | None) -> str | None:
    """Format a timestamp cleanly as UTC ISO-8601 with trailing Z (matching Pydantic serialization)."""
    if value is None:
        return None
    dt = normalize_audit_timestamp(value)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt.microsecond else dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_parser_name(parser_name: str | None) -> str | None:
    """Normalize parser class names and legacy aliases to one lowercase slug."""
    if parser_name is None:
        return None
    raw = str(parser_name).strip()
    if not raw:
        return None
    compact = re.sub(r"[\s-]+", "_", raw).lower()
    if compact in _PARSER_NAME_MAP:
        return _PARSER_NAME_MAP[compact]
    no_underscores = compact.replace("_", "")
    if no_underscores in _PARSER_NAME_MAP:
        return _PARSER_NAME_MAP[no_underscores]
    # Convert CamelCase class name like FooBarParser -> foo_bar
    stripped = raw[:-6] if raw.endswith("Parser") else raw
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", stripped).lower()
    return snake or compact


def normalize_audit_action(action: str | None) -> str:
    """Map legacy UPPER_CASE audit action strings to dotted lowercase convention."""
    raw = str(action or "").strip()
    if not raw:
        return "system.event"
    upper = raw.upper()
    if upper in _ACTION_MAP:
        return _ACTION_MAP[upper]
    if "." in raw:
        return raw.lower()
    if "_" in raw:
        head, tail = raw.split("_", 1)
        return f"{head.lower()}.{tail.lower()}"
    return raw.lower()


def matching_raw_actions(action_filter: str) -> set[str]:
    """Return canonical and legacy raw action values matching a filter query."""
    canon = normalize_audit_action(action_filter)
    candidates = set(_REVERSE_ACTION_MAP.get(canon, {canon}))
    candidates.add(action_filter)
    candidates.add(canon)
    return candidates


def build_evidence_audit_details(
    *,
    filename: str | None = None,
    file_size: int | None = None,
    file_type: str | None = None,
    sha256_hash: str | None = None,
    parser: str | None = None,
    events_extracted: int | None = None,
) -> dict[str, Any]:
    """Build the single canonical details dict for evidence audit entries."""
    return {
        "filename": filename,
        "file_size": file_size,
        "file_type": file_type,
        "sha256_hash": sha256_hash,
        "parser": canonical_parser_name(parser),
        "events_extracted": events_extracted,
    }


def normalize_audit_details_for_display(action: str, details: Any) -> Any:
    """Return a read-only normalized copy of details for display/export (never mutates DB)."""
    if not isinstance(details, dict):
        return details

    out = dict(details)
    is_evidence = normalize_audit_action(action).startswith("evidence.") or any(
        k in out for k in ("sha256", "sha256_hash", "file_name", "filename", "size_bytes", "file_size", "parser", "parser_used", "events_extracted")
    )
    if not is_evidence:
        return out

    filename = out.pop("filename", None) or out.pop("file_name", None)
    file_size = out.pop("file_size", None)
    if file_size is None:
        file_size = out.pop("size_bytes", None)
    else:
        out.pop("size_bytes", None)
    file_type = out.pop("file_type", None)
    sha256_hash = out.pop("sha256_hash", None) or out.pop("sha256", None)
    raw_parser = out.pop("parser", None) or out.pop("parser_used", None)
    parser = canonical_parser_name(raw_parser)
    events_extracted = out.pop("events_extracted", None)

    canonical = build_evidence_audit_details(
        filename=filename,
        file_size=file_size,
        file_type=file_type,
        sha256_hash=sha256_hash,
        parser=parser,
        events_extracted=events_extracted,
    )
    return {**canonical, **out}


def log_audit_event(
    db: Session,
    user: "User",
    action: str,
    resource: str,
    request: Request | None = None,
    case_id: uuid.UUID | None = None,
    details: dict | list | str | None = None,
    timestamp: datetime | None = None,
) -> "AuditLog":
    from app.db.models.audit_log import AuditLog

    ip_address = None
    user_agent = None

    if request is not None:
        if request.client is not None:
            ip_address = request.client.host

        user_agent = request.headers.get("user-agent")

    canonical_action = normalize_audit_action(action)
    normalized_details = (
        normalize_audit_details_for_display(canonical_action, details)
        if isinstance(details, dict)
        else details
    )

    audit_entry = AuditLog(
        user_id=user.id,
        case_id=case_id,
        action=canonical_action,
        resource=resource,
        ip_address=ip_address,
        user_agent=user_agent,
        details=normalized_details,
        timestamp=normalize_audit_timestamp(timestamp) if timestamp is not None else utc_now(),
    )

    db.add(audit_entry)
    return audit_entry
