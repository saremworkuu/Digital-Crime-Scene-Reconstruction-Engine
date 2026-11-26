import hashlib
import io
import stat
import tempfile
import threading
import uuid
import logging
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Optional, List

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
    status,
    Request,
    Query,
)
from fastapi.responses import FileResponse
from sqlalchemy import select, func, delete
from sqlalchemy.orm import Session, sessionmaker

from app.core.dependencies import get_current_user
from app.core.config import settings
from app.db.models.case import Case, CaseStatus
from app.db.models.evidence import Evidence, ParsingStatus
from app.db.models.events import Event
from app.db.models.event_evidence import EventEvidence
from app.db.models.detection_event import DetectionEvent
from app.db.models.user import User
from app.db.session import get_db
from app.parsers.registry import get_parser
from app.parsers.auth_log import AuthLogParser
from app.parsers.web_access import WebAccessParser
from app.parsers.generic_csv_json import GenericCSVJSONParser
from app.parsers.log_parser import LogFileParser
from app.parsers.txt_parser import TextFileParser

from app.schemas.evidence import (
    EvidenceResponse,
    EvidenceUploadResult,
    EvidenceBatchResponse,
    ZipExtractionStatusResponse,
    ReparseRequest,
)
from app.services.normalizer import normalize_records
from app.services.event_service import save_normalized_events
from app.services.audit import (
    build_evidence_audit_details,
    canonical_parser_name,
    log_audit_event,
    utc_now,
)
from app.core.permissions import get_authorized_case

router = APIRouter()

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
MAX_ZIP_FILES = 100
MAX_ZIP_TOTAL_SIZE = 250 * 1024 * 1024  # 250 MB total extracted bytes across archive
CHUNK_SIZE = 1024 * 1024  # 1 MB
_ZIP_JUNK_NAMES = {".ds_store", "thumbs.db", "desktop.ini"}
_ZIP_JOB_LOCK = threading.Lock()
_ZIP_JOB_STATUS: dict[str, dict] = {}

ALLOWED_EXTENSIONS = {
    "",
    ".log",
    ".txt",
    ".evtx",
    ".pcap",
    ".pcapng",
    ".csv",
    ".json",
    ".auth",
    ".access",
    ".audit",
    ".dat",
    ".bin",
    ".syslog",
    ".reg",
    ".dump",
    ".raw",
    ".xml",
    ".gz",
    ".zip",
    ".tar",
}

# Keep evidence under the configured data directory. In production, point
# UPLOAD_DIR at a persistent mounted volume so files survive service restarts.
UPLOAD_DIR = Path(settings.UPLOAD_DIR).expanduser() / "evidence"


def _normalize_parser_slug(pname: Optional[str]) -> Optional[str]:
    if not pname:
        return None
    low = pname.lower()
    if "pcap" in low:
        return "pcap_summary"
    if "evtx" in low:
        return "windows_evtx"
    if "auth" in low or "syslog" in low:
        return "linux_auth"
    if "web" in low or "access" in low or "nginx" in low or "apache" in low:
        return "web_server"
    if "csv" in low or "json" in low or "txt" in low or "generic" in low:
        return "generic_json_csv"
    return pname


def to_evidence_response(
    evidence: Evidence,
    db: Session,
    *,
    duplicate: bool = False,
    duplicate_of: Optional[uuid.UUID] = None,
) -> EvidenceResponse:
    """Enriches Evidence with event counts and display labels matching frontend."""
    evt_count = db.execute(
        select(func.count(EventEvidence.event_id)).where(EventEvidence.evidence_id == evidence.id)
    ).scalar() or 0

    if evt_count == 0:
        evt_count = db.execute(
            select(func.count(Event.id)).where(Event.evidence_id == evidence.id)
        ).scalar() or 0

    uploader_name = "Lead Forensics"
    try:
        uploader = db.get(User, evidence.uploaded_by)
        if uploader and hasattr(uploader, "username") and isinstance(uploader.username, str):
            uploader_name = uploader.username
    except Exception:
        pass

    status_str = "Parsed" if evidence.parsing_status == ParsingStatus.PARSED else (
        "Failed" if evidence.parsing_status == ParsingStatus.FAILED else "Pending"
    )

    # Read a short raw sample from the file if available
    raw_sample = None
    try:
        fpath = Path(evidence.file_path)
        if fpath.exists() and fpath.stat().st_size > 0:
            with open(fpath, "rb") as f:
                header = f.read(512)
                raw_sample = header.decode("utf-8", errors="replace")[:250]
    except Exception:
        pass

    norm_parser = _normalize_parser_slug(evidence.parser_used)

    ev_id = evidence.id if isinstance(evidence.id, uuid.UUID) else (uuid.UUID(str(evidence.id)) if str(evidence.id or "").strip() and str(evidence.id) != "None" else uuid.uuid4())
    up_time = evidence.uploaded_at if isinstance(evidence.uploaded_at, datetime) else utc_now()
    up_by = evidence.uploaded_by if isinstance(evidence.uploaded_by, uuid.UUID) else (uuid.UUID(str(evidence.uploaded_by)) if str(evidence.uploaded_by or "").strip() and str(evidence.uploaded_by) != "None" else uuid.uuid4())

    from app.services.report import is_container_evidence
    is_container = is_container_evidence(evidence, event_count=evt_count)
    if is_container and not evidence.parser_used:
        norm_parser = "ZipArchive"

    parsed_at_dt = None
    parsed_audit_details = None
    try:
        from app.db.models.audit_log import AuditLog
        parsed_log = db.execute(
            select(AuditLog)
            .where(
                AuditLog.resource == f"evidence:{ev_id}",
                AuditLog.action.in_(["evidence.parsed", "EVIDENCE_PARSED"]),
            )
            .order_by(AuditLog.timestamp.desc())
        ).scalars().first()
        if parsed_log is not None:
            parsed_at_dt = parsed_log.timestamp
            if isinstance(parsed_log.details, dict):
                parsed_audit_details = parsed_log.details
    except Exception:
        pass

    extracted_count: Optional[int] = None
    if is_container:
        with _ZIP_JOB_LOCK:
            job = _ZIP_JOB_STATUS.get(str(ev_id))
            if job is not None:
                job_items = job.get("extracted_results") or []
                stored_in_job = sum(1 for item in job_items if getattr(item, "evidence", None) is not None)
                extracted_count = stored_in_job if stored_in_job > 0 else int(job.get("completed") or 0)
        if extracted_count is None and isinstance(db, Session) and evidence.filename:
            marker = f"extracted from {evidence.filename}:"
            child_descriptions = db.execute(
                select(Evidence.description).where(
                    Evidence.case_id == evidence.case_id,
                    Evidence.id != ev_id,
                    Evidence.description.isnot(None),
                )
            ).scalars().all()
            marker_lower = marker.lower()
            extracted_count = sum(1 for desc in child_descriptions if marker_lower in str(desc or "").lower())
        if (extracted_count is None or extracted_count == 0) and isinstance(parsed_audit_details, dict):
            audit_total = parsed_audit_details.get("extracted_total")
            if audit_total is not None:
                extracted_count = int(audit_total)

    return EvidenceResponse(
        id=ev_id,
        case_id=evidence.case_id if isinstance(evidence.case_id, uuid.UUID) else uuid.uuid4(),
        uploaded_by=up_by,
        filename=evidence.filename or "unknown",
        description=evidence.description or "",
        file_type=evidence.file_type or "application/octet-stream",
        file_size=evidence.file_size or 0,
        sha256_hash=evidence.sha256_hash or "",
        uploaded_at=up_time,
        received_at=up_time,
        parsed_at=parsed_at_dt,
        parsing_status=evidence.parsing_status or ParsingStatus.PENDING,
        parsing_error=evidence.parsing_error,
        parser_used=norm_parser or evidence.parser_used or "auto",
        size_bytes=evidence.file_size or 0,
        status=status_str,
        uploader_name=uploader_name,
        uploader_id=str(up_by),
        event_count=evt_count,
        raw_sample=raw_sample,
        duplicate=duplicate,
        duplicate_of=duplicate_of,
        is_container=is_container,
        extracted_count=extracted_count,
    )


def count_case_artifacts(db: Session, case_ids: List[uuid.UUID]) -> dict[uuid.UUID, int]:
    """Count non-container Evidence artifacts per case using existing container classification."""
    if not case_ids:
        return {}
    from app.services.report import is_container_evidence

    rows = db.execute(
        select(Evidence.id, Evidence.case_id, Evidence.parser_used, Evidence.filename)
        .where(Evidence.case_id.in_(case_ids))
    ).all()
    if not rows:
        return {cid: 0 for cid in case_ids}

    legacy_zip_ids = [
        ev_id
        for ev_id, _cid, parser_used, filename in rows
        if (parser_used or "").strip() != "ZipArchive"
        and str(filename or "").strip().lower().endswith(".zip")
    ]
    evt_counts_by_id: dict[uuid.UUID, int] = {}
    if legacy_zip_ids:
        for ev_id, cnt in db.execute(
            select(EventEvidence.evidence_id, func.count(EventEvidence.event_id))
            .where(EventEvidence.evidence_id.in_(legacy_zip_ids))
            .group_by(EventEvidence.evidence_id)
        ).all():
            evt_counts_by_id[ev_id] = int(cnt or 0)
        missing_ev_ids = [eid for eid in legacy_zip_ids if evt_counts_by_id.get(eid, 0) == 0]
        if missing_ev_ids:
            for ev_id, cnt in db.execute(
                select(Event.evidence_id, func.count(Event.id))
                .where(Event.evidence_id.in_(missing_ev_ids))
                .group_by(Event.evidence_id)
            ).all():
                evt_counts_by_id[ev_id] = int(cnt or 0)

    counts: dict[uuid.UUID, int] = {cid: 0 for cid in case_ids}
    for ev_id, cid, parser_used, filename in rows:
        item = {"parser_used": parser_used, "filename": filename}
        if is_container_evidence(item, event_count=evt_counts_by_id.get(ev_id, 0)):
            continue
        counts[cid] = counts.get(cid, 0) + 1
    return counts


def _apply_single_host_inference(
    db: Session,
    case_id: uuid.UUID,
    records: list[dict],
) -> list[dict]:
    """Resolve host aliases (NetFlow/PCAP/WAF) and infer host for hostless records in single-host cases."""
    from app.services.entity_classification import (
        build_host_alias_map,
        is_ip_address,
        is_netflow_pcap_or_waf,
        resolve_endpoint_alias,
    )

    if not records:
        return records

    def _valid_known_host(details: dict | None) -> Optional[str]:
        if not isinstance(details, dict):
            return None
        if details.get("host_inferred"):
            return None
        h = str(details.get("host") or "").strip()
        if not h or h.casefold() in {"unknown", "unknown_host", "-", "n/a"} or h.isdigit() or is_ip_address(h):
            return None
        return h

    existing_events: list[Event] = []
    if isinstance(db, Session):
        existing_events = db.execute(
            select(Event).where(Event.case_id == case_id)
        ).scalars().all()

    alias_map = build_host_alias_map([*existing_events, *records])
    if alias_map:
        for rec in records:
            details = rec.get("details")
            if not isinstance(details, dict):
                continue
            cur = str(details.get("host") or "").strip()
            if cur in alias_map:
                details["host"] = alias_map[cur]
                details["host_inferred"] = True
            elif is_netflow_pcap_or_waf(rec):
                endpoint_host = resolve_endpoint_alias(rec, alias_map)
                if endpoint_host and (
                    not cur
                    or cur.casefold() in {"unknown", "unknown_host", "-"}
                    or is_ip_address(cur)
                    or details.get("host_inferred")
                ):
                    details["host"] = endpoint_host
                    details["host_inferred"] = True

        updated_alias_rows = False
        for ev_row in existing_events:
            det = ev_row.details if isinstance(ev_row.details, dict) else None
            if not det:
                continue
            cur = str(det.get("host") or "").strip()
            resolved_host = None
            if cur in alias_map:
                resolved_host = alias_map[cur]
            elif is_netflow_pcap_or_waf(ev_row):
                endpoint_host = resolve_endpoint_alias(ev_row, alias_map)
                if endpoint_host and (
                    not cur
                    or cur.casefold() in {"unknown", "unknown_host", "-"}
                    or is_ip_address(cur)
                    or det.get("host_inferred")
                ):
                    resolved_host = endpoint_host
            if resolved_host and resolved_host != cur:
                new_det = dict(det)
                new_det["host"] = resolved_host
                new_det["host_inferred"] = True
                ev_row.details = new_det
                updated_alias_rows = True
        if updated_alias_rows and isinstance(db, Session):
            db.flush()

    known_hosts = {
        h
        for h in (_valid_known_host(rec.get("details")) for rec in records)
        if h
    }
    if existing_events and len(known_hosts) <= 1:
        for ev_row in existing_events:
            h = _valid_known_host(ev_row.details if isinstance(ev_row.details, dict) else None)
            if h:
                known_hosts.add(h)
                if len(known_hosts) > 1:
                    break

    if len(known_hosts) == 1:
        single_host = next(iter(known_hosts))
        for rec in records:
            details = rec.get("details")
            if isinstance(details, dict):
                cur = str(details.get("host") or "").strip()
                if not cur or cur.casefold() in {"unknown", "unknown_host", "-"}:
                    details["host"] = single_host
                    details["host_inferred"] = True
        if existing_events:
            updated_any = False
            for ev_row in existing_events:
                det = ev_row.details if isinstance(ev_row.details, dict) else None
                if not det:
                    continue
                cur = str(det.get("host") or "").strip()
                is_web_like = str(ev_row.event_type or "").lower() == "web_access" or is_netflow_pcap_or_waf(ev_row)
                should_backfill = (
                    not cur or cur.casefold() in {"unknown", "unknown_host", "-"}
                    or (is_web_like and det.get("host_inferred") and (cur == det.get("src_ip") or is_ip_address(cur)))
                )
                if should_backfill:
                    new_det = dict(det)
                    new_det["host"] = single_host
                    new_det["host_inferred"] = True
                    ev_row.details = new_det
                    updated_any = True
            if updated_any and isinstance(db, Session):
                db.flush()
    return records


def resolve_parser(file_path: Path, filename: str, parser_type: Optional[str] = None):
    """Dispatches to designated parser or auto-selects from registry."""
    ext = Path(filename).suffix.lower()

    # Format-accurate dispatch based on unambiguous file extensions first if
    # a generic fallback slug was sent alongside an XML/EVTX/PCAP/audit file.
    if ext in (".pcap", ".pcapng", ".xml"):
        return get_parser(file_path, original_filename=filename)

    if ext == ".evtx":
        from app.parsers.windows_evtx import WindowsEVTXParser
        return WindowsEVTXParser()

    # Manual parser override if provided
    if parser_type and parser_type.lower() != "auto":
        ptype = parser_type.lower()
        if ptype in ("windows_evtx", "evtx", "xml", "sysmon"):
            from app.parsers.windows_evtx import WindowsEVTXParser
            return WindowsEVTXParser()
        if ptype in ("pcap_summary", "pcap", "pcapng"):
            from app.parsers.pcap import PCAPParser
            return PCAPParser()
        if ptype in ("generic_json_csv", "generic", "csv", "json"):
            if ext in (".csv", ".json"):
                from app.parsers.generic_csv_json import GenericCSVJSONParser
                return GenericCSVJSONParser()
        if ptype in ("linux_auth", "auth"):
            from app.parsers.auth_log import AuthLogParser
            return AuthLogParser()
        if ptype in ("web_server", "access", "nginx", "apache"):
            from app.parsers.web_access import WebAccessParser
            return WebAccessParser()
        if ptype in ("structured_log", "audit", "log"):
            return get_parser(file_path, original_filename=filename) or LogFileParser()

    return get_parser(file_path, original_filename=filename)


def _store_uploaded_file_and_record(
    request: Request,
    case_id: uuid.UUID | str,
    file: UploadFile,
    description: str,
    current_user: User,
    db: Session,
    *,
    parser_name_for_audit: Optional[str] = None,
) -> tuple[Evidence, Path, str, datetime, bool]:
    """Validate, hash (SHA-256), deduplicate by (case_id, sha256), store bytes, create Evidence & audit entry."""
    case = get_authorized_case(
        case_id=case_id,
        current_user=current_user,
        db=db,
        allow_viewer=False,
    )

    if case.status == CaseStatus.CLOSED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot add evidence to a closed case.",
        )

    if not file.filename or not file.filename.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A filename is required.",
        )

    filename = Path(file.filename.replace("\\", "/")).name
    if filename in ("", ".", "..") or len(filename) > 255:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename.",
        )

    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file extension.",
        )

    stored_filename = f"{uuid.uuid4().hex}.bin"
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    file_path = UPLOAD_DIR / stored_filename

    sha256 = hashlib.sha256()
    file_size = 0
    database_committed = False

    try:
        file.file.seek(0)
    except Exception:
        pass

    try:
        with file_path.open("xb") as destination:
            while True:
                chunk = file.file.read(CHUNK_SIZE)
                if not chunk:
                    break
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="File exceeds the 100 MB limit.",
                    )
                sha256.update(chunk)
                destination.write(chunk)

        if file_size == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Empty files are not allowed.",
            )

        sha256_hex = sha256.hexdigest()

        # Idempotency guard: never create a duplicate Evidence row or re-parse when
        # the exact same byte content (SHA-256) is already stored in this case.
        existing_ev = None
        if isinstance(db, Session):
            existing_ev = db.execute(
                select(Evidence)
                .where(
                    Evidence.case_id == case.id,
                    Evidence.sha256_hash == sha256_hex,
                    Evidence.parsing_status.in_([ParsingStatus.PARSED, ParsingStatus.PENDING]),
                )
                .order_by(Evidence.uploaded_at.asc())
            ).scalars().first()

        if isinstance(existing_ev, Evidence):
            if file_path.exists():
                file_path.unlink()
            log_audit_event(
                db=db,
                user=current_user,
                action="evidence.duplicate_skipped",
                resource=f"evidence:{existing_ev.id}",
                request=request,
                case_id=existing_ev.case_id,
                timestamp=utc_now(),
                details={
                    **build_evidence_audit_details(
                        filename=filename,
                        file_size=file_size,
                        file_type=file.content_type or "application/octet-stream",
                        sha256_hash=sha256_hex,
                        parser=parser_name_for_audit or getattr(existing_ev, "parser_used", None),
                        events_extracted=0,
                    ),
                    "existing_evidence_id": str(existing_ev.id),
                    "existing_filename": existing_ev.filename,
                    "duplicate": True,
                },
            )
            db.commit()
            return existing_ev, Path(existing_ev.file_path), filename, existing_ev.uploaded_at, True

        received_at = utc_now()
        evidence = Evidence(
            case_id=case.id,
            uploaded_by=current_user.id,
            filename=filename,
            description=description or "",
            file_type=file.content_type or "application/octet-stream",
            file_path=str(file_path),
            sha256_hash=sha256_hex,
            file_size=file_size,
            uploaded_at=received_at,
            parsing_status=ParsingStatus.PENDING,
            parser_used=parser_name_for_audit,
        )
        db.add(evidence)
        db.flush()

        log_audit_event(
            db=db,
            user=current_user,
            action="evidence.uploaded",
            resource=f"evidence:{evidence.id}",
            request=request,
            case_id=evidence.case_id,
            timestamp=received_at,
            details={
                **build_evidence_audit_details(
                    filename=evidence.filename,
                    file_size=evidence.file_size,
                    file_type=evidence.file_type,
                    sha256_hash=evidence.sha256_hash,
                    parser=parser_name_for_audit,
                    events_extracted=0,
                ),
                "received_at": received_at.isoformat(),
            },
        )
        db.commit()
        database_committed = True
        db.refresh(evidence)
        return evidence, file_path, filename, received_at, False

    except Exception:
        db.rollback()
        if not database_committed and file_path.exists():
            file_path.unlink()
        raise


def _validate_zip_member_path(raw_name: str) -> tuple[bool, Optional[str]]:
    """Return (should_skip, leaf_filename) or raise HTTPException on unsafe traversal/symlink path."""
    if "\x00" in raw_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsafe zip member path rejected: {raw_name!r}",
        )
    normalized = raw_name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) >= 2 and normalized[1] == ":"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Absolute path inside zip archive is not allowed: {raw_name}",
        )
    parts = PurePosixPath(normalized).parts
    if any(part == ".." for part in parts):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Zip-slip path traversal detected in archive member: {raw_name}",
        )
    if any(part == "__MACOSX" for part in parts):
        return True, None
    leaf = PurePosixPath(normalized).name
    if not leaf or leaf.lower() in _ZIP_JUNK_NAMES or leaf.startswith("._"):
        return True, None
    return False, leaf


def _collect_safe_zip_members(zip_path: Path) -> List[tuple[zipfile.ZipInfo, str]]:
    """Validate zip archive structure, block zip-slip/symlinks/zip-bombs, and return safe member list."""
    try:
        zf_ctx = zipfile.ZipFile(zip_path, "r")
    except zipfile.BadZipFile:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded .zip file is invalid or corrupted.",
        )

    members: List[tuple[zipfile.ZipInfo, str]] = []
    total_streamed = 0

    with zf_ctx as zf:
        for info in zf.infolist():
            mode = (info.external_attr >> 16) & 0o170000
            if stat.S_ISLNK(mode):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Symbolic link inside zip archive is not allowed: {info.filename}",
                )

            if info.is_dir() or info.filename.endswith(("/", "\\")):
                # Validate directory names for traversal too
                _validate_zip_member_path(info.filename)
                continue

            should_skip, leaf_name = _validate_zip_member_path(info.filename)
            if should_skip or not leaf_name:
                continue

            if len(members) >= MAX_ZIP_FILES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Zip archive exceeds maximum allowed limit of {MAX_ZIP_FILES} files.",
                )

            # Stream member to verify real uncompressed byte sizes (do not trust header metadata alone)
            member_bytes = 0
            try:
                with zf.open(info, "r") as zmember:
                    while True:
                        chunk = zmember.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        member_bytes += len(chunk)
                        total_streamed += len(chunk)
                        if member_bytes > MAX_FILE_SIZE:
                            raise HTTPException(
                                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                detail=f"Extracted member '{leaf_name}' exceeds the 100 MB limit.",
                            )
                        if total_streamed > MAX_ZIP_TOTAL_SIZE:
                            raise HTTPException(
                                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                detail="Zip archive total uncompressed size exceeds the 250 MB safety limit.",
                            )
            except HTTPException:
                raise
            except Exception as ex:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Could not read zip member '{info.filename}': {ex}",
                )

            members.append((info, leaf_name))

    return members


def _process_zip_members_bg(
    db_bind,
    zip_evidence_id: uuid.UUID,
    zip_case_id: uuid.UUID,
    zip_filename: str,
    zip_path: Path,
    description: str,
    user_id: uuid.UUID,
    received_at: datetime,
    safe_members: List[tuple[zipfile.ZipInfo, str]],
    client_ip: str,
    user_agent: str,
) -> None:
    """Extract and ingest zip archive members one by one in a background session."""
    zip_key = str(zip_evidence_id)
    audit_req = SimpleNamespace(
        client=SimpleNamespace(host=client_ip),
        headers={"user-agent": user_agent} if user_agent else {},
    )
    SessionFactory = sessionmaker(bind=db_bind, autoflush=False, autocommit=False)
    bg_db = SessionFactory()
    extracted_results: List[EvidenceUploadResult] = []
    any_parsed = False

    try:
        bg_user = bg_db.get(User, user_id)
        if bg_user is None:
            raise RuntimeError(f"User {user_id} no longer available for zip extraction.")

        with zipfile.ZipFile(zip_path, "r") as zf:
            for info, leaf_name in safe_members:
                spool = tempfile.SpooledTemporaryFile(max_size=10 * 1024 * 1024)
                try:
                    with zf.open(info, "r") as zmember:
                        while True:
                            chunk = zmember.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            spool.write(chunk)
                    spool.seek(0)

                    member_upload = UploadFile(file=spool, filename=leaf_name)
                    member_desc = (
                        f"{description} (extracted from {zip_filename}: {info.filename})".strip()
                        if description
                        else f"Extracted from {zip_filename}: {info.filename}"
                    )
                    child_ev, member_is_dup = _create_single_evidence(
                        request=audit_req,
                        case_id=zip_case_id,
                        file=member_upload,
                        description=member_desc,
                        current_user=bg_user,
                        db=bg_db,
                        parser_type=None,
                        run_detections=False,
                    )
                    child_resp = to_evidence_response(
                        child_ev,
                        bg_db,
                        duplicate=member_is_dup,
                        duplicate_of=child_ev.id if member_is_dup else None,
                    )
                    if member_is_dup:
                        extracted_results.append(
                            EvidenceUploadResult(
                                filename=leaf_name,
                                status="duplicate",
                                evidence=child_resp,
                            )
                        )
                    elif child_ev.parsing_status == ParsingStatus.FAILED:
                        extracted_results.append(
                            EvidenceUploadResult(
                                filename=leaf_name,
                                status="failed",
                                evidence=child_resp,
                                error=child_ev.parsing_error or "Parsing failed.",
                            )
                        )
                    else:
                        any_parsed = True
                        extracted_results.append(
                            EvidenceUploadResult(
                                filename=leaf_name,
                                status="success",
                                evidence=child_resp,
                            )
                        )
                except Exception as ex:
                    logging.warning("Zip member ingestion failed for %s: %s", leaf_name, ex)
                    extracted_results.append(
                        EvidenceUploadResult(
                            filename=leaf_name,
                            status="failed",
                            evidence=None,
                            error=str(getattr(ex, "detail", str(ex))),
                        )
                    )
                finally:
                    spool.close()

                with _ZIP_JOB_LOCK:
                    job = _ZIP_JOB_STATUS.get(zip_key)
                    if job is not None:
                        job["completed"] = len(extracted_results)
                        job["failed"] = sum(1 for r in extracted_results if r.status == "failed")
                        job["extracted_results"] = list(extracted_results)

        if any_parsed:
            try:
                from app.api.v1.detections import _execute_case_detections
                _execute_case_detections(zip_case_id, bg_db)
            except Exception as de:
                logging.warning("Error running detections after zip extraction: %s", de)

        zip_ev = bg_db.get(Evidence, zip_evidence_id)
        if zip_ev is not None:
            parsed_at = utc_now()
            success_count = sum(1 for r in extracted_results if r.status == "success")
            dup_count = sum(1 for r in extracted_results if r.status == "duplicate")
            failed_count = sum(1 for r in extracted_results if r.status == "failed")
            zip_ev.parser_used = "ZipArchive"
            zip_ev.parsing_status = (
                ParsingStatus.PARSED
                if (success_count + dup_count) > 0 or not extracted_results
                else ParsingStatus.FAILED
            )
            zip_ev.parsing_error = (
                f"{failed_count} member(s) failed inside archive."
                if failed_count > 0 and (success_count + dup_count) == 0
                else None
            )
            total_events_from_members = sum(
                (r.evidence.event_count if r.evidence else 0) for r in extracted_results
            )
            log_audit_event(
                db=bg_db,
                user=bg_user,
                action="evidence.parsed",
                resource=f"evidence:{zip_ev.id}",
                request=audit_req,
                case_id=zip_ev.case_id,
                timestamp=parsed_at,
                details={
                    **build_evidence_audit_details(
                        filename=zip_ev.filename,
                        file_size=zip_ev.file_size,
                        file_type=zip_ev.file_type,
                        sha256_hash=zip_ev.sha256_hash,
                        parser="ZipArchive",
                        events_extracted=total_events_from_members,
                    ),
                    "received_at": received_at.isoformat(),
                    "parsed_at": parsed_at.isoformat(),
                    "extracted_total": len(extracted_results),
                    "extracted_succeeded": success_count,
                    "extracted_duplicates": dup_count,
                    "extracted_failed": failed_count,
                },
            )
            bg_db.commit()

        final_status = "parsed" if any_parsed or not extracted_results or any(r.status == "duplicate" for r in extracted_results) else "failed"
        with _ZIP_JOB_LOCK:
            _ZIP_JOB_STATUS[zip_key] = {
                "status": final_status,
                "total": len(safe_members),
                "completed": len(extracted_results),
                "failed": sum(1 for r in extracted_results if r.status == "failed"),
                "extracted_results": list(extracted_results),
            }
    except Exception as exc:
        logging.exception("Background zip extraction failed for %s", zip_filename)
        try:
            bg_db.rollback()
            zip_ev = bg_db.get(Evidence, zip_evidence_id)
            if zip_ev is not None:
                zip_ev.parsing_status = ParsingStatus.FAILED
                zip_ev.parsing_error = f"Archive extraction failed: {exc}"
                bg_db.commit()
        except Exception:
            bg_db.rollback()
        with _ZIP_JOB_LOCK:
            _ZIP_JOB_STATUS[zip_key] = {
                "status": "failed",
                "total": len(safe_members),
                "completed": len(extracted_results),
                "failed": max(1, sum(1 for r in extracted_results if r.status != "success")),
                "extracted_results": list(extracted_results),
            }
    finally:
        bg_db.close()


def _get_zip_status_payload(ev: Evidence, db: Session) -> dict:
    """Return current archive extraction progress dict from memory or reconstruct from DB."""
    with _ZIP_JOB_LOCK:
        job = _ZIP_JOB_STATUS.get(str(ev.id))
        if job is not None:
            return {
                "status": job["status"],
                "total": job["total"],
                "completed": job["completed"],
                "failed": job["failed"],
                "extracted_results": list(job["extracted_results"]),
            }

    marker = f"extracted from {ev.filename}:"
    case_items = db.execute(
        select(Evidence).where(Evidence.case_id == ev.case_id, Evidence.id != ev.id)
    ).scalars().all()
    results = []
    for child in case_items:
        if marker.lower() in str(child.description or "").lower():
            resp = to_evidence_response(child, db)
            results.append(
                EvidenceUploadResult(
                    filename=child.filename,
                    status="failed" if child.parsing_status == ParsingStatus.FAILED else "success",
                    evidence=resp,
                    error=child.parsing_error,
                )
            )
    status_str = "pending" if ev.parsing_status == ParsingStatus.PENDING else (
        "failed" if ev.parsing_status == ParsingStatus.FAILED else "parsed"
    )
    return {
        "status": status_str,
        "total": len(results),
        "completed": len(results),
        "failed": sum(1 for r in results if r.status == "failed"),
        "extracted_results": results,
    }


def _ingest_zip_evidence(
    request: Request,
    case_id: uuid.UUID | str,
    file: UploadFile,
    description: str,
    current_user: User,
    db: Session,
    background_tasks: Optional[BackgroundTasks] = None,
) -> tuple[Evidence, List[EvidenceUploadResult], bool]:
    """Store and hash original .zip archive, validate safety limits, then schedule/run member ingestion."""
    # Pre-validate zip archive in a temporary file before storing archive record so malicious zips
    # (zip-slip / zip-bomb / corrupt) never leave partial records or extracted artifacts behind.
    try:
        file.file.seek(0)
    except Exception:
        pass

    tmp_check = tempfile.SpooledTemporaryFile(max_size=10 * 1024 * 1024)
    try:
        total_zip_bytes = 0
        while True:
            chunk = file.file.read(CHUNK_SIZE)
            if not chunk:
                break
            total_zip_bytes += len(chunk)
            if total_zip_bytes > MAX_FILE_SIZE:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="File exceeds the 100 MB limit.",
                )
            tmp_check.write(chunk)
        if total_zip_bytes == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Empty files are not allowed.",
            )
        tmp_check.seek(0)
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as named_tmp:
            named_tmp_path = Path(named_tmp.name)
            while True:
                buf = tmp_check.read(CHUNK_SIZE)
                if not buf:
                    break
                named_tmp.write(buf)
        try:
            safe_members = _collect_safe_zip_members(named_tmp_path)
        finally:
            if named_tmp_path.exists():
                named_tmp_path.unlink()
    finally:
        tmp_check.close()

    try:
        file.file.seek(0)
    except Exception:
        pass

    zip_evidence, zip_path, _zip_filename, received_at, is_duplicate = _store_uploaded_file_and_record(
        request=request,
        case_id=case_id,
        file=file,
        description=description,
        current_user=current_user,
        db=db,
        parser_name_for_audit="ZipArchive",
    )

    if is_duplicate:
        existing_payload = _get_zip_status_payload(zip_evidence, db)
        dup_results = [
            EvidenceUploadResult(
                filename=item.filename,
                status="duplicate" if item.status == "success" else item.status,
                evidence=(
                    item.evidence.model_copy(
                        update={"duplicate": True, "duplicate_of": item.evidence.id}
                    )
                    if item.evidence is not None
                    else None
                ),
                error=item.error,
            )
            for item in existing_payload["extracted_results"]
        ]
        return zip_evidence, dup_results, True

    zip_key = str(zip_evidence.id)
    with _ZIP_JOB_LOCK:
        _ZIP_JOB_STATUS[zip_key] = {
            "status": "pending",
            "total": len(safe_members),
            "completed": 0,
            "failed": 0,
            "extracted_results": [],
        }

    client_ip = request.client.host if getattr(request, "client", None) else "0.0.0.0"
    user_agent = request.headers.get("user-agent", "") if getattr(request, "headers", None) else ""
    db_bind = db.get_bind()

    if background_tasks is not None:
        background_tasks.add_task(
            _process_zip_members_bg,
            db_bind,
            zip_evidence.id,
            zip_evidence.case_id,
            zip_evidence.filename,
            zip_path,
            description,
            current_user.id,
            received_at,
            safe_members,
            client_ip,
            user_agent,
        )
        return zip_evidence, [], False

    _process_zip_members_bg(
        db_bind,
        zip_evidence.id,
        zip_evidence.case_id,
        zip_evidence.filename,
        zip_path,
        description,
        current_user.id,
        received_at,
        safe_members,
        client_ip,
        user_agent,
    )
    db.refresh(zip_evidence)
    with _ZIP_JOB_LOCK:
        results = list((_ZIP_JOB_STATUS.get(zip_key) or {}).get("extracted_results") or [])
    return zip_evidence, results, False


def _create_single_evidence(
    request: Request,
    case_id: uuid.UUID | str,
    file: UploadFile,
    description: str,
    current_user: User,
    db: Session,
    parser_type: Optional[str] = None,
    run_detections: bool = True,
) -> tuple[Evidence, bool]:
    evidence, file_path, filename, received_at, is_duplicate = _store_uploaded_file_and_record(
        request=request,
        case_id=case_id,
        file=file,
        description=description,
        current_user=current_user,
        db=db,
        parser_name_for_audit=None,
    )
    if is_duplicate:
        return evidence, True

    try:
        parser = resolve_parser(file_path, filename, parser_type)
        canonical_parser = canonical_parser_name(parser.__class__.__name__) if parser is not None else None

        # Parse evidence
        if parser is None:
            evidence.parsing_status = ParsingStatus.FAILED
            evidence.parsing_error = "No suitable parser was found for this file format."
        else:
            evidence.parser_used = parser.__class__.__name__
            try:
                records = parser.parse(file_path, original_filename=filename)
                normalized_records = normalize_records(records, default_filename=filename)
                _apply_single_host_inference(db, evidence.case_id, normalized_records)
                # A4: pass the real upload time so event_service can store
                # ingested_at in details separately from the evidence event_time.
                save_normalized_events(
                    db=db,
                    case_id=evidence.case_id,
                    evidence_id=evidence.id,
                    records=normalized_records,
                    ingested_at=received_at,
                )
                parsed_at = utc_now()
                evidence.parsing_status = ParsingStatus.PARSED
                evidence.parsing_error = None
                log_audit_event(
                    db=db,
                    user=current_user,
                    action="evidence.parsed",
                    resource=f"evidence:{evidence.id}",
                    request=request,
                    case_id=evidence.case_id,
                    timestamp=parsed_at,
                    details={
                        **build_evidence_audit_details(
                            filename=evidence.filename,
                            file_size=evidence.file_size,
                            file_type=evidence.file_type,
                            sha256_hash=evidence.sha256_hash,
                            parser=canonical_parser,
                            events_extracted=len(normalized_records),
                        ),
                        "received_at": received_at.isoformat(),
                        "parsed_at": parsed_at.isoformat(),
                    },
                )
                if run_detections:
                    try:
                        from app.api.v1.detections import _execute_case_detections
                        _execute_case_detections(evidence.case_id, db)
                    except Exception as de:
                        logging.warning("Error running detections post-upload: %s", de)
            except Exception as pe:
                db.rollback()
                evidence = db.get(Evidence, evidence.id)
                evidence.parsing_status = ParsingStatus.FAILED
                evidence.parsing_error = f"Parsing failed: {str(pe)}"
                logging.exception("Parsing failed for %s", filename)

        db.commit()
        db.refresh(evidence)
        return evidence, False

    except Exception:
        db.rollback()
        raise


# Upload single or batch evidence directly under /evidence/
@router.post("/")
def upload_evidence_batch(
    request: Request,
    background_tasks: BackgroundTasks,
    case_id: uuid.UUID,
    files: Optional[List[UploadFile]] = File(None),
    file: Optional[UploadFile] = File(None),
    description: str = Form(""),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    upload_list = []
    if files:
        upload_list.extend(files)
    if file:
        upload_list.append(file)

    if not upload_list:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Upload at least one file.",
        )

    # If single file upload endpoint was invoked via `file`
    if file is not None and not files:
        from fastapi.responses import JSONResponse
        from fastapi.encoders import jsonable_encoder
        if Path((file.filename or "").replace("\\", "/")).suffix.lower() == ".zip":
            ev, extracted_results, is_dup = _ingest_zip_evidence(
                request=request,
                case_id=case_id,
                file=file,
                description=description,
                current_user=current_user,
                db=db,
                background_tasks=background_tasks,
            )
            resp = to_evidence_response(
                ev, db, duplicate=is_dup, duplicate_of=ev.id if is_dup else None
            )
            resp.extracted_results = extracted_results
            return JSONResponse(
                status_code=status.HTTP_201_CREATED,
                content=jsonable_encoder(resp),
            )
        ev, is_dup = _create_single_evidence(
            request=request,
            case_id=case_id,
            file=file,
            description=description,
            current_user=current_user,
            db=db,
        )
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=jsonable_encoder(
                to_evidence_response(ev, db, duplicate=is_dup, duplicate_of=ev.id if is_dup else None)
            ),
        )

    results = []
    for uploaded_file in upload_list:
        fname = uploaded_file.filename or "unnamed"
        try:
            if Path(fname.replace("\\", "/")).suffix.lower() == ".zip":
                ev, extracted_results, is_dup = _ingest_zip_evidence(
                    request=request,
                    case_id=case_id,
                    file=uploaded_file,
                    description=description,
                    current_user=current_user,
                    db=db,
                )
                zip_resp = to_evidence_response(
                    ev, db, duplicate=is_dup, duplicate_of=ev.id if is_dup else None
                )
                zip_resp.extracted_results = extracted_results
                results.append(
                    EvidenceUploadResult(
                        filename=fname,
                        status="duplicate" if is_dup else "success",
                        evidence=zip_resp,
                    )
                )
                results.extend(extracted_results)
                continue

            ev, is_dup = _create_single_evidence(
                request=request,
                case_id=case_id,
                file=uploaded_file,
                description=description,
                current_user=current_user,
                db=db,
            )
            results.append(
                EvidenceUploadResult(
                    filename=fname,
                    status="duplicate" if is_dup else "success",
                    evidence=to_evidence_response(
                        ev, db, duplicate=is_dup, duplicate_of=ev.id if is_dup else None
                    ),
                )
            )
        except Exception as ex:
            results.append(
                EvidenceUploadResult(
                    filename=fname,
                    status="failed",
                    evidence=None,
                    error=str(getattr(ex, "detail", str(ex))),
                )
            )

    return EvidenceBatchResponse(
        total=len(results),
        successful=sum(r.status in ("success", "duplicate") for r in results),
        failed=sum(r.status == "failed" for r in results),
        results=results,
    )


# Upload single evidence directly to /cases/{case_id}/evidence/upload or /cases/{case_id}/evidence
@router.post("/cases/{case_id}/evidence/upload", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
@router.post("/cases/{case_id}/evidence", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
def upload_case_evidence(
    request: Request,
    background_tasks: BackgroundTasks,
    case_id: str,
    file: UploadFile = File(...),
    description: Optional[str] = Form(""),
    parser_type: Optional[str] = Form(None),
    file_type: Optional[str] = Form(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if Path((file.filename or "").replace("\\", "/")).suffix.lower() == ".zip":
        ev, extracted_results, is_dup = _ingest_zip_evidence(
            request=request,
            case_id=case_id,
            file=file,
            description=description or "",
            current_user=current_user,
            db=db,
            background_tasks=background_tasks,
        )
        resp = to_evidence_response(
            ev, db, duplicate=is_dup, duplicate_of=ev.id if is_dup else None
        )
        resp.extracted_results = extracted_results
        return resp

    actual_parser = parser_type or file_type
    ev, is_dup = _create_single_evidence(
        request=request,
        case_id=case_id,
        file=file,
        description=description or "",
        current_user=current_user,
        db=db,
        parser_type=actual_parser,
    )
    return to_evidence_response(
        ev, db, duplicate=is_dup, duplicate_of=ev.id if is_dup else None
    )


@router.get("/cases/{case_id}/evidence/{evidence_id}/status", response_model=ZipExtractionStatusResponse)
def get_zip_extraction_status(
    case_id: str,
    evidence_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return archive extraction progress and per-member ingestion statuses."""
    case = get_authorized_case(
        case_id=case_id,
        current_user=current_user,
        db=db,
        allow_viewer=True,
    )
    ev = db.get(Evidence, evidence_id)
    if ev is None or ev.case_id != case.id:
        raise HTTPException(status_code=404, detail="Evidence not found.")

    payload = _get_zip_status_payload(ev, db)
    return ZipExtractionStatusResponse(
        evidence_id=ev.id,
        case_id=ev.case_id,
        status=payload["status"],
        parsing_status=ev.parsing_status,
        total=payload["total"],
        completed=payload["completed"],
        failed=payload["failed"],
        extracted_results=payload["extracted_results"],
    )


def _list_evidence_core(request: Request, case_id: uuid.UUID | str, current_user: User, db: Session):
    case = get_authorized_case(
        case_id=case_id,
        current_user=current_user,
        db=db,
        allow_viewer=True,
    )

    items = db.execute(
        select(Evidence)
        .where(Evidence.case_id == case.id)
        .order_by(Evidence.uploaded_at.desc())
    ).scalars().all()

    return [to_evidence_response(item, db) for item in items]


# List evidence for a case via query parameter (?case_id=...)
@router.get("", response_model=List[EvidenceResponse])
@router.get("/", response_model=List[EvidenceResponse], include_in_schema=False)
def list_evidence_by_query(
    request: Request,
    case_id: str = Query(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _list_evidence_core(request, case_id, current_user, db)


# List evidence for a case via path parameter (/cases/{case_id}/evidence)
@router.get("/cases/{case_id}/evidence", response_model=List[EvidenceResponse])
def list_case_evidence(
    request: Request,
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _list_evidence_core(request, case_id, current_user, db)


@router.post("/{evidence_id}/reparse", response_model=EvidenceResponse)
def reparse_evidence(
    evidence_id: uuid.UUID,
    payload: Optional[ReparseRequest] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found.")

    get_authorized_case(
        case_id=evidence.case_id,
        current_user=current_user,
        db=db,
        allow_viewer=False,
    )

    from app.services.report import is_container_evidence
    if is_container_evidence(evidence):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Archive containers cannot be reparsed as a single evidence log.",
        )

    file_path = Path(evidence.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Stored evidence file not found on disk.")

    parser_type = payload.parser_type if payload else None
    parser = resolve_parser(file_path, evidence.filename, parser_type)
    if parser is None:
        evidence.parsing_status = ParsingStatus.FAILED
        evidence.parsing_error = "No suitable parser found for this format."
    else:
        evidence.parser_used = parser.__class__.__name__
        try:
            records = parser.parse(file_path, original_filename=evidence.filename)
            normalized = normalize_records(records, default_filename=evidence.filename)
            _apply_single_host_inference(db, evidence.case_id, normalized)
            save_normalized_events(
                db=db,
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                records=normalized,
            )
            parsed_at = utc_now()
            evidence.parsing_status = ParsingStatus.PARSED
            evidence.parsing_error = None
            received_iso = (
                evidence.uploaded_at.isoformat()
                if hasattr(evidence.uploaded_at, "isoformat")
                else str(evidence.uploaded_at)
            )
            log_audit_event(
                db=db,
                user=current_user,
                action="evidence.parsed",
                resource=f"evidence:{evidence.id}",
                request=request,
                case_id=evidence.case_id,
                timestamp=parsed_at,
                details={
                    **build_evidence_audit_details(
                        filename=evidence.filename,
                        file_size=evidence.file_size,
                        file_type=evidence.file_type,
                        sha256_hash=evidence.sha256_hash,
                        parser=parser.__class__.__name__,
                        events_extracted=len(normalized),
                    ),
                    "received_at": received_iso,
                    "parsed_at": parsed_at.isoformat(),
                },
            )
            try:
                from app.api.v1.detections import _execute_case_detections
                _execute_case_detections(evidence.case_id, db)
            except Exception as de:
                logging.warning("Error running detections post-reparse: %s", de)
        except Exception as e:
            evidence.parsing_status = ParsingStatus.FAILED
            evidence.parsing_error = f"Re-parsing failed: {str(e)}"

    db.commit()
    db.refresh(evidence)
    return to_evidence_response(evidence, db)


@router.delete("/{evidence_id}")
def delete_evidence(
    evidence_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found.")

    case = get_authorized_case(
        case_id=evidence.case_id,
        current_user=current_user,
        db=db,
        allow_viewer=False,
    )

    if getattr(case, "legal_hold", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'Deletion Blocked: Case "{case.name}" is currently locked under Legal Hold.',
        )

    # Clean up detection/evidence associations before deleting the events. Some
    # SQLite deployments do not enforce the database's ON DELETE CASCADE rules.
    event_ids = select(Event.id).where(Event.evidence_id == evidence.id)
    db.execute(delete(DetectionEvent).where(DetectionEvent.event_id.in_(event_ids)))
    db.execute(delete(EventEvidence).where(EventEvidence.evidence_id == evidence.id))
    db.execute(delete(Event).where(Event.evidence_id == evidence.id))

    # Remove stored physical file if exists
    try:
        fpath = Path(evidence.file_path)
        if fpath.exists():
            fpath.unlink()
    except Exception:
        pass

    log_audit_event(
        db=db,
        user=current_user,
        action="evidence.deleted",
        resource=f"evidence:{evidence.id}",
        request=request,
        case_id=case.id,
        details=build_evidence_audit_details(
            filename=evidence.filename,
            file_size=evidence.file_size,
            file_type=evidence.file_type,
            sha256_hash=evidence.sha256_hash,
            parser=evidence.parser_used,
            events_extracted=0,
        ),
    )

    db.delete(evidence)
    db.commit()
    return {"message": "Evidence deleted successfully", "id": str(evidence_id)}


@router.get("/{evidence_id}/download")
def download_evidence(
    evidence_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found.")

    case = get_authorized_case(
        case_id=evidence.case_id,
        current_user=current_user,
        db=db,
        allow_viewer=False,
    )

    storage_dir = UPLOAD_DIR.resolve()
    file_path = Path(evidence.file_path).resolve()

    if not file_path.is_relative_to(storage_dir) or not file_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Stored evidence file not found.",
        )

    log_audit_event(
        db=db,
        user=current_user,
        action="evidence.downloaded",
        resource=f"evidence:{evidence.id}",
        request=request,
        case_id=case.id,
        details=build_evidence_audit_details(
            filename=evidence.filename,
            file_size=evidence.file_size,
            file_type=evidence.file_type,
            sha256_hash=evidence.sha256_hash,
            parser=evidence.parser_used,
            events_extracted=None,
        ),
    )
    db.commit()

    return FileResponse(
        path=str(file_path),
        filename=evidence.filename,
        media_type="application/octet-stream",
    )
