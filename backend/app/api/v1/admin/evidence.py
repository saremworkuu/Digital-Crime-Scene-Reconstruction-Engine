import hashlib
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.permissions import require_admin
from app.db.models.case import Case
from app.db.models.event_evidence import EventEvidence
from app.db.models.events import Event
from app.db.models.evidence import Evidence
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.admin import (
    AdminEvidenceResponse,
    AdminEvidenceVerifyResponse,
)
from app.services.audit import build_evidence_audit_details, log_audit_event

router = APIRouter(dependencies=[Depends(require_admin)])


def to_admin_evidence_response(
    e: Evidence,
    db: Session,
    *,
    users_by_id: Optional[Dict[uuid.UUID, User]] = None,
    legacy_zip_event_counts: Optional[Dict[uuid.UUID, int]] = None,
) -> AdminEvidenceResponse:
    if users_by_id is not None:
        uploader_u = users_by_id.get(e.uploaded_by) if e.uploaded_by else None
    else:
        uploader_u = db.get(User, e.uploaded_by) if e.uploaded_by else None
    uploader_name = uploader_u.username if uploader_u else "Unknown"

    status_str = e.parsing_status.value if hasattr(e.parsing_status, "value") else str(e.parsing_status)
    if status_str == "parsed":
        status_str = "completed"

    expected = e.expected_sha256 or e.sha256_hash
    uploaded_str = e.uploaded_at.isoformat() if hasattr(e.uploaded_at, "isoformat") else str(e.uploaded_at)

    file_ext = (e.file_type or "LOG").upper()
    if "." in file_ext:
        file_ext = file_ext.replace(".", "").upper()

    from app.services.report import is_container_evidence
    evt_count = 0
    if (e.parser_used or "").strip() != "ZipArchive" and str(e.filename or "").strip().lower().endswith(".zip"):
        if legacy_zip_event_counts is not None:
            evt_count = legacy_zip_event_counts.get(e.id, 0)
        else:
            has_evt = db.execute(select(Event.id).where(Event.evidence_id == e.id).limit(1)).first() is not None
            evt_count = 1 if has_evt else 0
    is_container = is_container_evidence(e, event_count=evt_count)

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
        is_container=is_container,
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
    rows = db.execute(
        select(Evidence, User, Case.name)
        .outerjoin(User, Evidence.uploaded_by == User.id)
        .outerjoin(Case, Evidence.case_id == Case.id)
        .order_by(Evidence.uploaded_at.desc())
    ).all()
    if not rows:
        return []

    users_by_id: Dict[uuid.UUID, User] = {
        u.id: u for _, u, _ in rows if u is not None
    }
    cases_by_id: Dict[uuid.UUID, str] = {
        e.case_id: (cname or "") for e, _, cname in rows if e.case_id
    }

    legacy_zip_ids = [
        e.id
        for e, _, _ in rows
        if (e.parser_used or "").strip() != "ZipArchive"
        and str(e.filename or "").strip().lower().endswith(".zip")
    ]
    legacy_zip_event_counts: Dict[uuid.UUID, int] = {}
    if legacy_zip_ids:
        for ev_id, cnt in db.execute(
            select(Event.evidence_id, func.count(Event.id))
            .where(Event.evidence_id.in_(legacy_zip_ids))
            .group_by(Event.evidence_id)
        ).all():
            legacy_zip_event_counts[ev_id] = int(cnt or 0)

    results = []
    search_q = search.lower().strip() if search else None
    type_q = type.lower() if type and type != "all" else None
    status_q = status.lower() if status and status != "all" else None

    for e, _, _ in rows:
        resp = to_admin_evidence_response(
            e,
            db,
            users_by_id=users_by_id,
            legacy_zip_event_counts=legacy_zip_event_counts,
        )

        if case_id and case_id != "all":
            c_name = cases_by_id.get(e.case_id, "")
            if resp.case_id != case_id and case_id not in c_name.lower().replace(" ", "-"):
                continue

        if type_q and resp.type.lower() != type_q:
            continue

        if status_q and resp.parsing_status.lower() != status_q:
            continue

        if search_q:
            if (
                search_q not in resp.file_name.lower()
                and search_q not in resp.uploader.lower()
                and search_q not in resp.sha256.lower()
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
    if ev.file_path:
        fpath = Path(ev.file_path)
        if fpath.exists() and fpath.is_file():
            hasher = hashlib.sha256()
            with open(fpath, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            computed_hash = hasher.hexdigest()

    expected_hash = ev.expected_sha256 or ev.sha256_hash
    match = computed_hash.lower() == expected_hash.lower()

    ev.verified = match
    ev.sha256_hash = computed_hash

    log_audit_event(
        db=db,
        user=current_admin,
        action="evidence.verified",
        resource=f"evidence:{ev.id}",
        case_id=ev.case_id,
        details={
            **build_evidence_audit_details(
                filename=ev.filename,
                file_size=ev.file_size,
                file_type=ev.file_type,
                sha256_hash=computed_hash,
                parser=ev.parser_used,
                events_extracted=None,
            ),
            "match": match,
            "expected_sha256": expected_hash,
        },
    )

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

    parent_case = db.get(Case, ev.case_id)
    if parent_case and getattr(parent_case, "legal_hold", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'Deletion Blocked: Case "{parent_case.name}" is currently locked under Legal Hold.',
        )

    db.execute(delete(EventEvidence).where(EventEvidence.evidence_id == ev.id))
    db.execute(delete(Event).where(Event.evidence_id == ev.id))

    try:
        if ev.file_path:
            fpath = Path(ev.file_path)
            if fpath.exists():
                fpath.unlink()
    except Exception:
        pass

    ev_info = build_evidence_audit_details(
        filename=ev.filename,
        file_size=ev.file_size,
        file_type=ev.file_type,
        sha256_hash=ev.sha256_hash,
        parser=ev.parser_used,
        events_extracted=0,
    )
    case_id_ref = ev.case_id

    db.delete(ev)
    log_audit_event(
        db=db,
        user=current_admin,
        action="evidence.deleted",
        resource=f"evidence:{evidence_id}",
        case_id=case_id_ref,
        details=ev_info,
    )

    db.commit()
    return {"message": "Evidence deleted successfully", "id": evidence_id}
