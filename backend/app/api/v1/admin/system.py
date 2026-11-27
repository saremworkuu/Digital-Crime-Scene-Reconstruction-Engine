import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.v1.evidence import count_case_artifacts
from app.core.config import settings
from app.core.permissions import require_admin
from app.db.models.audit_log import AuditLog
from app.db.models.case import Case
from app.db.models.contact_message import ContactMessage
from app.db.models.evidence import Evidence, ParsingStatus
from app.db.models.login_attempt import LoginAttempt
from app.db.models.system_settings import SystemSettings
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.admin import (
    AdminDashboardSummaryResponse,
    AdminParserStatus,
    AdminQueueJob,
    AdminSettingsResponse,
    AdminSettingsUpdateRequest,
    AdminSystemHealthResponse,
)
from app.services.audit import canonical_parser_name, log_audit_event, normalize_audit_timestamp, utc_now

router = APIRouter(dependencies=[Depends(require_admin)])

_REGISTERED_PARSER_TYPES = [
    ("auth_log", "AUTH_LOG"),
    ("web_access", "WEB_ACCESS"),
    ("auditd", "AUDITD"),
    ("mysql_general", "MYSQL"),
    ("windows_evtx", "EVTX"),
    ("pcap", "PCAP"),
    ("generic_csv_json", "CSV/JSON"),
    ("vuln_scan", "XML"),
    ("log_parser", "LOG"),
    ("txt_parser", "TXT"),
]


def _normalize_parser_bucket(parser_used: str | None, file_type: str | None, filename: str | None) -> str | None:
    raw_parser = (parser_used or "").strip()
    if raw_parser == "ZipArchive":
        return None
    if raw_parser:
        canon = canonical_parser_name(raw_parser)
        for key, label in _REGISTERED_PARSER_TYPES:
            if canon == key:
                return label
        return canon.upper()

    ext = Path(filename or "").suffix.lower().lstrip(".")
    ftype = (file_type or "").lower()
    if ext in ("csv", "json") or "csv" in ftype or "json" in ftype:
        return "CSV/JSON"
    if ext in ("pcap", "pcapng") or "pcap" in ftype:
        return "PCAP"
    if ext == "evtx" or "evtx" in ftype:
        return "EVTX"
    if ext == "xml" or "xml" in ftype:
        return "XML"
    if ext == "txt":
        return "TXT"
    if ext in ("log", "auth", "access", "syslog"):
        return "LOG"
    return (ext or "LOG").upper()


def _build_real_queue(db: Session, limit: int = 25) -> List[AdminQueueJob]:
    queue_rows = db.execute(
        select(Evidence)
        .where(
            Evidence.parsing_status.in_([ParsingStatus.PENDING, ParsingStatus.FAILED]),
            or_(Evidence.parser_used.is_(None), Evidence.parser_used != "ZipArchive"),
        )
        .order_by(Evidence.uploaded_at.desc())
        .limit(limit)
    ).scalars().all()

    jobs: List[AdminQueueJob] = []
    for ev in queue_rows:
        status_str = ev.parsing_status.value if hasattr(ev.parsing_status, "value") else str(ev.parsing_status)
        mapped_status = "failed" if status_str == "failed" else "processing"
        parser_label = _normalize_parser_bucket(ev.parser_used, ev.file_type, ev.filename) or "LOG"
        started_str = ev.uploaded_at.isoformat() if hasattr(ev.uploaded_at, "isoformat") else str(ev.uploaded_at)
        jobs.append(
            AdminQueueJob(
                id=str(ev.id),
                file_name=ev.filename,
                parser_type=parser_label,
                status=mapped_status,
                started_at=started_str,
                error=ev.parsing_error,
            )
        )
    return jobs


def _get_disk_total_bytes() -> int:
    upload_path = Path(settings.UPLOAD_DIR).expanduser()
    check_path = upload_path if upload_path.exists() else Path(".")
    try:
        return int(shutil.disk_usage(check_path).total)
    except Exception:
        return 0


@router.get("/summary", response_model=AdminDashboardSummaryResponse)
def get_admin_dashboard_summary(db: Session = Depends(get_db)):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    # Roundtrip 1: fetch all scalar dashboard counts in a single SQL query
    counts_row = db.execute(
        select(
            select(func.count(User.id)).scalar_subquery(),
            select(func.count(Case.id)).where(Case.is_deleted.is_(False)).scalar_subquery(),
            select(func.count(Evidence.id))
            .where(Evidence.parsing_status == ParsingStatus.FAILED)
            .scalar_subquery(),
            select(func.count(ContactMessage.id))
            .where(
                or_(
                    ContactMessage.status == "new",
                    (ContactMessage.is_read.is_(False))
                    & (~ContactMessage.status.in_(["archived", "spam"])),
                )
            )
            .scalar_subquery(),
            select(func.count(LoginAttempt.id))
            .where(LoginAttempt.failed_at >= cutoff)
            .scalar_subquery(),
        )
    ).one()

    user_count, case_count, failure_count, new_messages, failed_24h = (
        int(counts_row[0] or 0),
        int(counts_row[1] or 0),
        int(counts_row[2] or 0),
        int(counts_row[3] or 0),
        int(counts_row[4] or 0),
    )

    # Roundtrip 2: fetch lightweight Evidence metadata + Case.is_deleted for container exclusion & queue
    from app.api.v1.evidence import count_case_artifacts
    from app.db.models.events import Event

    ev_rows = db.execute(
        select(
            Evidence.id,
            Evidence.case_id,
            Evidence.filename,
            Evidence.file_type,
            Evidence.parser_used,
            Evidence.parsing_status,
            Evidence.parsing_error,
            Evidence.uploaded_at,
        )
        .join(Case, Evidence.case_id == Case.id)
        .where(Case.is_deleted.is_(False))
        .order_by(Evidence.uploaded_at.desc())
    ).all()

    from app.services.report import is_container_evidence

    legacy_zip_ids = [
        ev_id
        for ev_id, _cid, fname, _ft, parser_used, *_ in ev_rows
        if (parser_used or "").strip() != "ZipArchive"
        and str(fname or "").strip().lower().endswith(".zip")
    ]
    evt_counts_by_id: Dict[uuid.UUID, int] = {}
    if legacy_zip_ids:
        for ev_id, cnt in db.execute(
            select(Event.evidence_id, func.count(Event.id))
            .where(Event.evidence_id.in_(legacy_zip_ids))
            .group_by(Event.evidence_id)
        ).all():
            evt_counts_by_id[ev_id] = int(cnt or 0)

    evidence_count = 0
    queue: List[AdminQueueJob] = []
    for ev_id, _cid, fname, ftype, parser_used, pstatus, perror, uploaded_at in ev_rows:
        is_container = is_container_evidence(
            {"parser_used": parser_used, "filename": fname},
            event_count=evt_counts_by_id.get(ev_id, 0),
        )
        if not is_container:
            evidence_count += 1
        status_str = pstatus.value if hasattr(pstatus, "value") else str(pstatus)
        if (
            len(queue) < 8
            and status_str in ("pending", "failed")
            and (parser_used or "").strip() != "ZipArchive"
        ):
            mapped_status = "failed" if status_str == "failed" else "processing"
            parser_label = _normalize_parser_bucket(parser_used, ftype, fname) or "LOG"
            started_str = uploaded_at.isoformat() if hasattr(uploaded_at, "isoformat") else str(uploaded_at)
            queue.append(
                AdminQueueJob(
                    id=str(ev_id),
                    file_name=fname,
                    parser_type=parser_label,
                    status=mapped_status,
                    started_at=started_str,
                    error=perror,
                )
            )

    return AdminDashboardSummaryResponse(
        users=user_count,
        cases=case_count,
        evidence=evidence_count,
        failures=failure_count,
        new_messages=new_messages,
        failed_logins_24h=failed_24h,
        queue=queue,
    )


@router.get("/health", response_model=AdminSystemHealthResponse)
def get_system_health(db: Session = Depends(get_db)):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    # Roundtrip 1: storage_used + failed_24h in one scalar query
    scalar_row = db.execute(
        select(
            select(func.sum(Evidence.file_size)).scalar_subquery(),
            select(func.count(LoginAttempt.id)).where(LoginAttempt.failed_at >= cutoff).scalar_subquery(),
        )
    ).one()
    storage_used = int(scalar_row[0] or 0)
    storage_total = _get_disk_total_bytes() or max(storage_used, 1)
    failed_24h = int(scalar_row[1] or 0)

    # Roundtrip 2: single scan of lightweight Evidence columns for parsers, queue, and failed errors
    evidence_rows = db.execute(
        select(
            Evidence.id,
            Evidence.filename,
            Evidence.file_type,
            Evidence.parser_used,
            Evidence.parsing_status,
            Evidence.parsing_error,
            Evidence.uploaded_at,
        ).order_by(Evidence.uploaded_at.desc())
    ).all()

    stats_by_parser: Dict[str, Dict[str, int]] = {
        label: {"total": 0, "failed": 0} for _, label in _REGISTERED_PARSER_TYPES
    }
    queue: List[AdminQueueJob] = []
    recent_errors: List[dict] = []

    for ev_id, filename, file_type, parser_used, parsing_status, parsing_error, uploaded_at in evidence_rows:
        status_val = parsing_status.value if hasattr(parsing_status, "value") else str(parsing_status)
        bucket = _normalize_parser_bucket(parser_used, file_type, filename)
        if bucket:
            if bucket not in stats_by_parser:
                stats_by_parser[bucket] = {"total": 0, "failed": 0}
            stats_by_parser[bucket]["total"] += 1
            if status_val == "failed":
                stats_by_parser[bucket]["failed"] += 1

        if (
            len(queue) < 25
            and status_val in ("pending", "failed")
            and (parser_used or "").strip() != "ZipArchive"
        ):
            started_str = uploaded_at.isoformat() if hasattr(uploaded_at, "isoformat") else str(uploaded_at)
            queue.append(
                AdminQueueJob(
                    id=str(ev_id),
                    file_name=filename,
                    parser_type=bucket or "LOG",
                    status="failed" if status_val == "failed" else "processing",
                    started_at=started_str,
                    error=parsing_error,
                )
            )

        if len(recent_errors) < 15 and status_val == "failed":
            ts = normalize_audit_timestamp(uploaded_at)
            recent_errors.append(
                {
                    "timestamp": ts.isoformat(),
                    "component": f"{bucket or 'Parser'} Parser",
                    "message": parsing_error or f"Parsing failed for {filename}",
                }
            )

    parsers: List[AdminParserStatus] = []
    for label, counts in stats_by_parser.items():
        total = counts["total"]
        failed = counts["failed"]
        if total > 0:
            rate = f"{((total - failed) / total) * 100:.1f}%"
            parser_status = "degraded" if failed > 0 else "online"
            activity_label = "Active"
        else:
            rate = "N/A"
            parser_status = "online"
            activity_label = "Standby"
        parsers.append(
            AdminParserStatus(
                type=label,
                status=parser_status,
                success_rate=rate,
                avg_latency=activity_label,
                files_processed=total,
            )
        )

    # Roundtrip 3: recent error audit entries
    error_audit_rows = db.execute(
        select(AuditLog)
        .where(
            or_(
                AuditLog.action.ilike("%fail%"),
                AuditLog.action.ilike("%error%"),
            )
        )
        .order_by(AuditLog.timestamp.desc())
        .limit(10)
    ).scalars().all()

    for log_row in error_audit_rows:
        ts = normalize_audit_timestamp(log_row.timestamp)
        if ts < cutoff:
            continue
        detail_msg = ""
        if isinstance(log_row.details, dict):
            detail_msg = (
                log_row.details.get("reason")
                or log_row.details.get("error")
                or log_row.details.get("email")
                or str(log_row.resource or "")
            )
        recent_errors.append(
            {
                "timestamp": ts.isoformat(),
                "component": log_row.action,
                "message": detail_msg or f"Audit error on {log_row.resource}",
            }
        )

    recent_errors.sort(key=lambda item: item["timestamp"], reverse=True)

    return AdminSystemHealthResponse(
        parsers=parsers,
        queue=queue,
        storage_used_bytes=storage_used,
        storage_total_bytes=storage_total,
        failed_logins_24h=failed_24h,
        recent_errors=recent_errors[:20],
    )


@router.post("/queue/{job_id}/retry")
def retry_queue_job(
    job_id: str,
    request: Request,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        ev_uuid = uuid.UUID(job_id)
    except Exception:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence job {job_id} not found.")

    ev = db.get(Evidence, ev_uuid)
    if not ev:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence job {job_id} not found.")

    ev.parsing_status = ParsingStatus.PENDING
    ev.parsing_error = None

    client_ip = request.client.host if request and request.client else None
    log_audit_event(
        db=db,
        user=current_admin,
        case_id=ev.case_id,
        action="ingestion.retried",
        resource=f"evidence:{ev.id}",
        ip_address=client_ip,
        details={"job_id": job_id, "filename": ev.filename},
    )
    db.commit()

    return {
        "id": str(ev.id),
        "file_name": ev.filename,
        "parser_type": _normalize_parser_bucket(ev.parser_used, ev.file_type, ev.filename) or "LOG",
        "status": "processing",
        "started_at": utc_now().isoformat(),
    }


@router.get("/settings", response_model=AdminSettingsResponse)
def get_admin_settings(db: Session = Depends(get_db)):
    s = db.query(SystemSettings).filter(SystemSettings.id == "default").first()
    if not s:
        s = SystemSettings(id="default")
        db.add(s)
        db.commit()
        db.refresh(s)

    return AdminSettingsResponse(
        time_zone=s.time_zone,
        org_name=s.org_name,
        retention_days=s.retention_days,
        min_password_length=s.min_password_length,
        two_factor_enforced=s.two_factor_enforced,
        failed_login_lockout_limit=s.failed_login_lockout_limit,
    )


@router.patch("/settings", response_model=AdminSettingsResponse)
@router.put("/settings", response_model=AdminSettingsResponse)
def update_admin_settings(
    patch: AdminSettingsUpdateRequest,
    request: Request,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    s = db.query(SystemSettings).filter(SystemSettings.id == "default").first()
    if not s:
        s = SystemSettings(id="default")
        db.add(s)

    details = {}
    if patch.time_zone is not None:
        s.time_zone = patch.time_zone
        details["time_zone"] = patch.time_zone
    if patch.org_name is not None:
        s.org_name = patch.org_name
        details["org_name"] = patch.org_name
    if patch.retention_days is not None:
        s.retention_days = patch.retention_days
        details["retention_days"] = patch.retention_days
    if patch.min_password_length is not None:
        s.min_password_length = patch.min_password_length
        details["min_password_length"] = patch.min_password_length
    if patch.two_factor_enforced is not None:
        s.two_factor_enforced = patch.two_factor_enforced
        details["two_factor_enforced"] = patch.two_factor_enforced
    if patch.failed_login_lockout_limit is not None:
        s.failed_login_lockout_limit = patch.failed_login_lockout_limit
        details["failed_login_lockout_limit"] = patch.failed_login_lockout_limit

    client_ip = request.client.host if request and request.client else None
    log_audit_event(
        db=db,
        user=current_admin,
        action="system.settings_updated",
        resource="settings:global-settings",
        ip_address=client_ip,
        details=details,
    )

    db.commit()
    db.refresh(s)

    return AdminSettingsResponse(
        time_zone=s.time_zone,
        org_name=s.org_name,
        retention_days=s.retention_days,
        min_password_length=s.min_password_length,
        two_factor_enforced=s.two_factor_enforced,
        failed_login_lockout_limit=s.failed_login_lockout_limit,
    )
