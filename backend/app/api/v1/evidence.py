import hashlib
import uuid
import logging
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    UploadFile,
    status,
    Request
)
from fastapi.responses import FileResponse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.models.case import Case, CaseStatus
from app.db.models.evidence import Evidence,ParsingStatus
from app.db.models.user import User,UserRole
from app.db.session import get_db
from app.parsers.registry import get_parser

from app.schemas.evidence import (
    EvidenceResponse,
    EvidenceUploadResult,
    EvidenceBatchResponse,
)

from app.db.models.case_assignment import CaseAssignment
from app.db.models.audit_log import AuditLog
from app.services.normalizer import normalize_records
from app.services.event_service import save_normalized_events
from app.services.audit import log_audit_event
from app.core.permissions import get_authorized_case


router = APIRouter()

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
CHUNK_SIZE = 1024 * 1024  # 1 MB

ALLOWED_EXTENSIONS = {
    ".log",
    ".txt",
    ".evtx",
    ".pcap",
    ".pcapng",
    ".csv",
    ".json",
    ".auth",
}
  

# Run the application from the backend directory.
UPLOAD_DIR = Path("uploads") / "evidence"


def _create_single_evidence(
    request: Request,
    case_id: uuid.UUID,
    file: UploadFile,
    description: str,
    current_user: User,
    db: Session,
):
    # 1. Find the case.
    case = get_authorized_case(
        case_id=case_id,
        current_user=current_user,
        db=db,
        allow_viewer=False,
)
   
    # 3. Closed cases cannot receive new evidence.
    if case.status == CaseStatus.CLOSED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot add evidence to a closed case.",
        )

    # 4. Validate the supplied filename.
    if not file.filename or not file.filename.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A filename is required.",
        )

    # Remove any directory components supplied in the filename.
    filename = Path(file.filename.replace("\\", "/")).name

    if filename in ("", ".", "..") or len(filename) > 255:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename.",
        )
    
# Validate the file extension.
    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file extension.",
        )


    # 5. Generate a server-controlled storage name.
    stored_filename = f"{uuid.uuid4().hex}.bin"
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    file_path = UPLOAD_DIR / stored_filename

    sha256 = hashlib.sha256()
    file_size = 0

    try:
        database_committed = False
        # 6. Save the file while calculating its size and hash.
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

        # 7. Create the database record.
        evidence = Evidence(
            case_id=case.id,
            uploaded_by=current_user.id,
            filename=filename,
            description=description,
            file_type=file.content_type or "application/octet-stream",
            file_path=str(file_path),
            sha256_hash=sha256.hexdigest(),
            file_size=file_size,
        )

        db.add(evidence)

        audit_entry = log_audit_event(
            db=db,
            user=current_user,
            action="evidence.uploaded",
            resource=f"evidence:{evidence.id}",
            request=request,
            case_id=evidence.case_id,
            details={
                "filename": evidence.filename,
                "file_type": evidence.file_type,
                "file_size": evidence.file_size,
                "sha256_hash": evidence.sha256_hash,
            },
        )

        db.commit()
        database_committed = True
        db.refresh(evidence)
        

        # Save the ID before parsing can fail.
        evidence_id = evidence.id

        
        parser = get_parser(
            file_path,
            original_filename=filename,
        )

        if parser is None:
            evidence.parsing_status = ParsingStatus.FAILED
            evidence.parsing_error = "No suitable parser was found."
        else:
            evidence.parser_used = parser.__class__.__name__

            try:
                records = parser.parse(file_path, original_filename=filename)

                print(f"\nFile: {filename}")
                print(f"Parser returned {len(records)} records")

                for index, record in enumerate(records, start=1):
                    print(f"Record {index}: {record}")

                normalized_records = normalize_records(records)

                print(f"Normalized {len(normalized_records)} records")

                for index, record in enumerate(normalized_records, start=1):
                    print(f"Normalized record {index}: {record}")

                saved_count = save_normalized_events(
                    db=db,
                    case_id=evidence.case_id,
                    evidence_id=evidence.id,
                    records=normalized_records,
                )

                logging.info(
                    "Evidence processing: filename=%s, parsed_records=%d, "
                    "normalized_records=%d, saved_events=%d",
                    filename,
                    len(records),
                    len(normalized_records),
                    saved_count,
                )

                evidence.parsing_status = ParsingStatus.PARSED
                evidence.parsing_error = None

            except Exception:
                db.rollback()

                evidence = db.get(Evidence, evidence_id)
                if evidence is None:
                    raise

                evidence.parsing_status = ParsingStatus.FAILED
                evidence.parsing_error = (
                    "The file was uploaded, but parsing or event saving failed."
                )

                # Log the real error for debugging.
                logging.exception(
                    "Evidence parsing failed for evidence_id=%s",
                    evidence_id,
                )

        db.commit()
        db.refresh(evidence)
        
        return evidence

    except Exception:
        db.rollback()
        # Remove the stored file if saving or recording it fails.
        if not database_committed and file_path.exists():
            file_path.unlink()
        
        raise

    finally:
        file.file.close()




@router.post(
    "/",
    response_model=EvidenceBatchResponse,
    status_code=status.HTTP_200_OK,
)
def create_evidence(
    request: Request,
    case_id: uuid.UUID,
    files: list[UploadFile] = File(...),
    description: str = "",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Upload at least one file.",
        )

    if len(files) > 20:
        for uploaded_file in files:
            uploaded_file.file.close()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A maximum of 20 files can be uploaded at once.",
        )

    results = []

    try:
        for uploaded_file in files:
            filename = uploaded_file.filename or "unnamed"

            try:
                evidence = _create_single_evidence(
                    request=request,
                    case_id=case_id,
                    file=uploaded_file,
                    description=description,
                    current_user=current_user,
                    db=db,
                )

                results.append(
                    EvidenceUploadResult(
                        filename=filename,
                        status="success",
                        evidence=evidence,
                        error=None,
                    )
                )

            except HTTPException as exc:
                results.append(
                    EvidenceUploadResult(
                        filename=filename,
                        status="failed",
                        evidence=None,
                        error=str(exc.detail),
                    )
                )

            except Exception:
                logging.exception(
                    "Evidence upload failed for filename=%s",
                    filename,
                )

                results.append(
                    EvidenceUploadResult(
                        filename=filename,
                        status="failed",
                        evidence=None,
                        error="An unexpected error occurred.",
                    )
                )

    finally:
        for uploaded_file in files:
            if not uploaded_file.file.closed:
                uploaded_file.file.close()

    successful = sum(
        result.status == "success" for result in results
    )

    if successful == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "All file uploads failed.",
                "total": len(results),
                "successful": successful,
                "failed": len(results),
                "results": [
                    result.model_dump(mode="json")
                    for result in results
                ],
            },
    )

    return EvidenceBatchResponse(
        total=len(results),
        successful=successful,
        failed=len(results) - successful,
        results=results,
    )




@router.get("/", response_model=list[EvidenceResponse])
def list_evidence(
    request:Request,
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # 1. Find the case.
    case = get_authorized_case(
    case_id=case_id,
    current_user=current_user,
    db=db,
    allow_viewer=True,
)

    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found.",
        )

    

    # 3. Return evidence metadata for this case.
    result = db.execute(
    select(Evidence)
    .where(Evidence.case_id == case.id)
    .order_by(Evidence.uploaded_at.desc())
)

    evidence_items = result.scalars().all()

    log_audit_event(
        db=db,
        user=current_user,
        action="evidence.viewed",
        resource=f"case:{case.id}/evidence",
        request=request,
        case_id=case.id,
        details={
            "evidence_count": len(evidence_items),
            "view": "evidence_list",
        },
    )

    db.commit()

    return evidence_items



@router.get("/{evidence_id}/download")
def download_evidence(
    evidence_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # 1. Find the evidence record.
    evidence = db.get(Evidence, evidence_id)

    if evidence is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found.",
        )

    # 2. Check access to the case containing this evidence.
    case = get_authorized_case(
        case_id=evidence.case_id,
        current_user=current_user,
        db=db,
        allow_viewer=False,
    )

    # 3. Resolve the stored path and verify it is inside
    #    the evidence storage directory.
    storage_dir = UPLOAD_DIR.resolve()
    file_path = Path(evidence.file_path).resolve()

    if (
        not file_path.is_relative_to(storage_dir)
        or not file_path.is_file()
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Stored evidence file not found.",
        )

    # 4. Record the download in the audit log.
    log_audit_event(
        db=db,
        user=current_user,
        action="evidence.downloaded",
        resource=f"evidence:{evidence.id}",
        request=request,
        case_id=case.id,
        details={
            "filename": evidence.filename,
            "sha256_hash": evidence.sha256_hash,
            "file_size": evidence.file_size,
        },
    )

    db.commit()

    # 5. Return the original file without modifying its contents.
    return FileResponse(
        path=str(file_path),
        filename=evidence.filename,
        media_type="application/octet-stream",
    )
