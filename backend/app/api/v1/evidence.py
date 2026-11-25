import hashlib
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

from fastapi import (
    APIRouter,
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
from sqlalchemy.orm import Session

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
CHUNK_SIZE = 1024 * 1024  # 1 MB

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


def to_evidence_response(evidence: Evidence, db: Session) -> EvidenceResponse:
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

    parsed_at_dt = None
    try:
        from app.db.models.audit_log import AuditLog
        parsed_row = db.execute(
            select(AuditLog.timestamp)
            .where(
                AuditLog.resource == f"evidence:{ev_id}",
                AuditLog.action.in_(["evidence.parsed", "EVIDENCE_PARSED"]),
            )
            .order_by(AuditLog.timestamp.desc())
        ).scalars().first()
        if parsed_row is not None:
            parsed_at_dt = parsed_row
    except Exception:
        pass

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
    )


def _apply_single_host_inference(
    db: Session,
    case_id: uuid.UUID,
    records: list[dict],
) -> list[dict]:
    """Infer host for unknown_host records when the case has a single known non-numeric host."""
    if not records:
        return records

    def _valid_known_host(details: dict | None) -> Optional[str]:
        if not isinstance(details, dict):
            return None
        if details.get("host_inferred"):
            return None
        h = str(details.get("host") or "").strip()
        if not h or h.casefold() in {"unknown", "unknown_host", "-", "n/a"} or h.isdigit():
            return None
        return h

    known_hosts = {
        h
        for h in (_valid_known_host(rec.get("details")) for rec in records)
        if h
    }
    if isinstance(db, Session) and len(known_hosts) <= 1:
        existing_details = db.execute(
            select(Event.details).where(Event.case_id == case_id)
        ).scalars().all()
        for det in existing_details:
            h = _valid_known_host(det)
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
        if isinstance(db, Session):
            existing_events = db.execute(
                select(Event).where(Event.case_id == case_id)
            ).scalars().all()
            updated_any = False
            for ev_row in existing_events:
                det = ev_row.details if isinstance(ev_row.details, dict) else None
                if not det:
                    continue
                cur = str(det.get("host") or "").strip()
                is_web_like = str(ev_row.event_type or "").lower() == "web_access"
                should_backfill = (
                    not cur or cur.casefold() in {"unknown", "unknown_host", "-"}
                    or (is_web_like and det.get("host_inferred") and cur == det.get("src_ip"))
                )
                if should_backfill:
                    new_det = dict(det)
                    new_det["host"] = single_host
                    new_det["host_inferred"] = True
                    ev_row.details = new_det
                    updated_any = True
            if updated_any:
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


def _create_single_evidence(
    request: Request,
    case_id: uuid.UUID | str,
    file: UploadFile,
    description: str,
    current_user: User,
    db: Session,
    parser_type: Optional[str] = None,
) -> Evidence:
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

        received_at = utc_now()
        evidence = Evidence(
            case_id=case.id,
            uploaded_by=current_user.id,
            filename=filename,
            description=description or "",
            file_type=file.content_type or "application/octet-stream",
            file_path=str(file_path),
            sha256_hash=sha256.hexdigest(),
            file_size=file_size,
            uploaded_at=received_at,
            parsing_status=ParsingStatus.PENDING,
        )
        db.add(evidence)
        db.flush()

        parser = resolve_parser(file_path, filename, parser_type)
        canonical_parser = canonical_parser_name(parser.__class__.__name__) if parser is not None else None

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
                    parser=canonical_parser,
                    events_extracted=0,
                ),
                "received_at": received_at.isoformat(),
            },
        )
        db.commit()
        database_committed = True
        db.refresh(evidence)

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
        return evidence

    except Exception:
        db.rollback()
        if not database_committed and file_path.exists():
            file_path.unlink()
        raise


# Upload single or batch evidence directly under /evidence/
@router.post("/")
def upload_evidence_batch(
    request: Request,
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
        ev = _create_single_evidence(
            request=request,
            case_id=case_id,
            file=file,
            description=description,
            current_user=current_user,
            db=db,
        )
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=jsonable_encoder(to_evidence_response(ev, db)),
        )

    results = []
    for uploaded_file in upload_list:
        fname = uploaded_file.filename or "unnamed"
        try:
            ev = _create_single_evidence(
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
                    status="success",
                    evidence=to_evidence_response(ev, db),
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
        successful=sum(r.status == "success" for r in results),
        failed=sum(r.status != "success" for r in results),
        results=results,
    )


# Upload single evidence directly to /cases/{case_id}/evidence/upload or /cases/{case_id}/evidence
@router.post("/cases/{case_id}/evidence/upload", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
@router.post("/cases/{case_id}/evidence", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
def upload_case_evidence(
    request: Request,
    case_id: str,
    file: UploadFile = File(...),
    description: Optional[str] = Form(""),
    parser_type: Optional[str] = Form(None),
    file_type: Optional[str] = Form(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    actual_parser = parser_type or file_type
    ev = _create_single_evidence(
        request=request,
        case_id=case_id,
        file=file,
        description=description or "",
        current_user=current_user,
        db=db,
        parser_type=actual_parser,
    )
    return to_evidence_response(ev, db)


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
