import uuid
import hashlib
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import select, delete

from app.core.permissions import require_admin
from app.db.session import get_db
from app.db.models.evidence import Evidence
from app.db.models.case import Case
from app.db.models.user import User
from app.db.models.event_evidence import EventEvidence
from app.db.models.events import Event
from app.db.models.audit_log import AuditLog
from app.schemas.admin import (
    AdminEvidenceResponse,
    AdminEvidenceVerifyResponse,
)

router = APIRouter(dependencies=[Depends(require_admin)])


def to_admin_evidence_response(e: Evidence, db: Session) -> AdminEvidenceResponse:
    uploader_u = db.get(User, e.uploaded_by) if e.uploaded_by else None
    uploader_name = uploader_u.username if uploader_u else "Sarem Worku"

    status_str = e.parsing_status.value if hasattr(e.parsing_status, "value") else str(e.parsing_status)
    # Map parsed -> completed for frontend compatibility
    if status_str == "parsed":
        status_str = "completed"

    expected = e.expected_sha256 or e.sha256_hash
    uploaded_str = e.uploaded_at.isoformat() if hasattr(e.uploaded_at, "isoformat") else str(e.uploaded_at)

    file_ext = (e.file_type or "LOG").upper()
    if "." in file_ext:
        file_ext = file_ext.replace(".", "").upper()

    return AdminEvidenceResponse(
        id=str(e.id),
        case_id=str(e.case_id),
        file_name=e.filename,
        type=file_ext,
        size_bytes=e.file_size or 0,
        uploader=uploader_name,
        uploaded_at=uploaded_str,
        sha256=e.sha256_hash,
        expected_sha256=expected,
        parsing_status=status_str,
        error_text=e.parsing_error,
        verified=e.verified,
    )


def resolve_evidence(evidence_id: str, db: Session) -> Evidence:
    try:
        ev_uuid = uuid.UUID(evidence_id)
        ev = db.get(Evidence, ev_uuid)
        if ev:
            return ev
    except Exception:
        pass

    ev = db.execute(
        select(Evidence).where(Evidence.filename == evidence_id)
    ).scalars().first()

    if not ev:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found.")
    return ev


@router.get("", response_model=List[AdminEvidenceResponse])
@router.get("/", response_model=List[AdminEvidenceResponse])
def get_admin_evidence(
    case_id: Optional[str] = None,
    type: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = select(Evidence).order_by(Evidence.uploaded_at.desc())
    items = db.execute(query).scalars().all()

    results = []
    for e in items:
        resp = to_admin_evidence_response(e, db)

        if case_id and case_id != "all":
            # Match by uuid or case slug
            c = db.get(Case, e.case_id)
            c_name = c.name if c else ""
            if resp.case_id != case_id and case_id not in c_name.lower().replace(" ", "-"):
                continue

        if type and type != "all" and resp.type.lower() != type.lower():
            continue

        if status and status != "all" and resp.parsing_status.lower() != status.lower():
            continue

        if search:
            q = search.lower()
            if (
                q not in resp.file_name.lower()
                and q not in resp.uploader.lower()
                and q not in resp.sha256.lower()
            ):
                continue

        results.append(resp)

    return results


@router.post("/{evidence_id}/verify", response_model=AdminEvidenceVerifyResponse)
def verify_evidence_integrity(
    evidence_id: str,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    ev = resolve_evidence(evidence_id, db)

    computed_hash = ev.sha256_hash
    # If file exists on disk, compute real sha256
    if ev.file_path:
        fpath = Path(ev.file_path)
        if fpath.exists() and fpath.is_file():
            hasher = hashlib.sha256()
            with open(fpath, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            computed_hash = hasher.hexdigest()

    expected_hash = ev.expected_sha256 or ev.sha256_hash
    match = (computed_hash.lower() == expected_hash.lower())

    ev.verified = match
    ev.sha256_hash = computed_hash

    db.add(AuditLog(
        user_id=current_admin.id,
        case_id=ev.case_id,
        action="EVIDENCE_VERIFY",
        resource=f"evidence:{ev.id}",
        details={
            "file_name": ev.filename,
            "match": match,
            "sha256": computed_hash,
            "expected_sha256": expected_hash,
        }
    ))

    db.commit()
    db.refresh(ev)

    return AdminEvidenceVerifyResponse(
        verified=True,
        computed_sha256=computed_hash,
        expected_sha256=expected_hash,
        match=match,
    )


@router.delete("/{evidence_id}")
def delete_admin_evidence(
    evidence_id: str,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    ev = resolve_evidence(evidence_id, db)

    # Check legal hold on parent case
    parent_case = db.get(Case, ev.case_id)
    if parent_case and getattr(parent_case, "legal_hold", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'Deletion Blocked: Case "{parent_case.name}" is currently locked under Legal Hold.',
        )

    # Clean associations & events
    db.execute(delete(EventEvidence).where(EventEvidence.evidence_id == ev.id))
    db.execute(delete(Event).where(Event.evidence_id == ev.id))

    # Remove file on disk if exists
    try:
        if ev.file_path:
            fpath = Path(ev.file_path)
            if fpath.exists():
                fpath.unlink()
    except Exception:
        pass

    ev_info = {"file_name": ev.filename, "sha256": ev.sha256_hash}
    case_id_ref = ev.case_id

    db.delete(ev)
    db.add(AuditLog(
        user_id=current_admin.id,
        case_id=case_id_ref,
        action="EVIDENCE_DELETE",
        resource=f"evidence:{evidence_id}",
        details=ev_info
    ))

    db.commit()
    return {"message": "Evidence deleted successfully", "id": evidence_id}
