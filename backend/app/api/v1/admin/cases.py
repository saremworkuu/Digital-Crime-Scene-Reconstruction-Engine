import uuid
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import select, func, or_

from app.core.permissions import require_admin
from app.db.session import get_db
from app.db.models.case import Case, CaseStatus
from app.db.models.user import User
from app.db.models.evidence import Evidence
from app.db.models.case_assignment import CaseAssignment
from app.db.models.audit_log import AuditLog
from app.schemas.admin import (
    AdminCaseResponse,
    AdminCaseStatusUpdateRequest,
    AdminCaseAssignRequest,
    AdminCaseLegalHoldRequest,
    AdminCaseArchiveRequest,
)

router = APIRouter(dependencies=[Depends(require_admin)])


def to_admin_case_response(c: Case, db: Session) -> AdminCaseResponse:
    ev_count = db.execute(
        select(func.count(Evidence.id)).where(Evidence.case_id == c.id)
    ).scalar() or 0

    assigned_names = db.execute(
        select(User.username)
        .join(CaseAssignment, CaseAssignment.user_id == User.id)
        .where(CaseAssignment.case_id == c.id)
    ).scalars().all()

    owner_u = db.get(User, c.created_by)
    owner_name = owner_u.username if owner_u else "Sarem Worku"

    status_val = c.status.value if hasattr(c.status, "value") else str(c.status)
    created_str = c.created_at.isoformat() if hasattr(c.created_at, "isoformat") else str(c.created_at)

    return AdminCaseResponse(
        id=str(c.id),
        title=c.name,
        status=status_val,
        owner=owner_name,
        created_date=created_str,
        assigned_investigators=list(assigned_names),
        is_archived=bool(getattr(c, "is_archived", False)),
        legal_hold=bool(getattr(c, "legal_hold", False)),
        evidence_count=ev_count,
        description=c.description or "",
    )


def resolve_case(case_id: str, db: Session) -> Case:
    parsed_uuid = None
    try:
        parsed_uuid = uuid.UUID(case_id)
    except Exception:
        pass

    if parsed_uuid:
        c = db.get(Case, parsed_uuid)
        if c and not c.is_deleted:
            return c

    # Search by slug/name
    clean = case_id.replace("case-", "").replace("-", " ").strip()
    c = db.execute(
        select(Case).where(
            (Case.name.ilike(f"%{clean}%")) | (Case.description.ilike(f"%{clean}%")),
            Case.is_deleted.is_(False)
        )
    ).scalars().first()

    if not c:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")
    return c


@router.get("", response_model=List[AdminCaseResponse])
@router.get("/", response_model=List[AdminCaseResponse])
def get_admin_cases(
    status: Optional[str] = None,
    archived: Optional[bool] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = select(Case).where(Case.is_deleted.is_(False)).order_by(Case.created_at.desc())
    cases = db.execute(query).scalars().all()

    results = []
    for c in cases:
        resp = to_admin_case_response(c, db)

        if status and status != "all" and resp.status.lower() != status.lower():
            continue
        if archived is not None and resp.is_archived != archived:
            continue
        if search:
            q = search.lower()
            if (
                q not in resp.title.lower()
                and q not in resp.owner.lower()
                and q not in resp.description.lower()
                and not any(q in inv.lower() for inv in resp.assigned_investigators)
            ):
                continue

        results.append(resp)

    return results


@router.get("/{case_id}", response_model=AdminCaseResponse)
def get_admin_case_by_id(
    case_id: str,
    db: Session = Depends(get_db),
):
    c = resolve_case(case_id, db)
    return to_admin_case_response(c, db)


@router.patch("/{case_id}/status", response_model=AdminCaseResponse)
def update_case_status(
    case_id: str,
    body: AdminCaseStatusUpdateRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    c = resolve_case(case_id, db)
    old_status = c.status.value if hasattr(c.status, "value") else str(c.status)

    try:
        c.status = CaseStatus(body.status.lower())
    except Exception:
        c.status = CaseStatus.OPEN

    db.add(AuditLog(
        user_id=current_admin.id,
        case_id=c.id,
        action="CASE_STATUS_UPDATE",
        resource=f"case:{c.id}",
        details={"from": old_status, "to": body.status}
    ))

    db.commit()
    db.refresh(c)
    return to_admin_case_response(c, db)


@router.patch("/{case_id}/assign", response_model=AdminCaseResponse)
def assign_case_investigators(
    case_id: str,
    body: AdminCaseAssignRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    c = resolve_case(case_id, db)

    # Clear current assignments and re-assign
    from app.db.models.case_assignment import CaseAssignment
    from sqlalchemy import delete

    db.execute(delete(CaseAssignment).where(CaseAssignment.case_id == c.id))

    for inv_name in body.investigators:
        inv_user = db.execute(
            select(User).where(or_(User.username == inv_name, User.email == inv_name))
        ).scalar_one_or_none()

        if inv_user:
            db.add(CaseAssignment(
                id=uuid.uuid4(),
                case_id=c.id,
                user_id=inv_user.id,
                assigned_by=current_admin.id,
            ))

    db.add(AuditLog(
        user_id=current_admin.id,
        case_id=c.id,
        action="CASE_ASSIGNMENT",
        resource=f"case:{c.id}",
        details={"assigned_investigators": body.investigators}
    ))

    db.commit()
    db.refresh(c)
    return to_admin_case_response(c, db)


@router.patch("/{case_id}/legal-hold", response_model=AdminCaseResponse)
def toggle_case_legal_hold(
    case_id: str,
    body: AdminCaseLegalHoldRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    c = resolve_case(case_id, db)
    c.legal_hold = body.legal_hold

    action_name = "CASE_LEGAL_HOLD_SET" if body.legal_hold else "CASE_LEGAL_HOLD_REMOVED"
    db.add(AuditLog(
        user_id=current_admin.id,
        case_id=c.id,
        action=action_name,
        resource=f"case:{c.id}",
        details={"legal_hold": body.legal_hold, "reason": body.reason or "Admin command directive"}
    ))

    db.commit()
    db.refresh(c)
    return to_admin_case_response(c, db)


@router.patch("/{case_id}/archive", response_model=AdminCaseResponse)
def toggle_case_archive(
    case_id: str,
    body: AdminCaseArchiveRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    c = resolve_case(case_id, db)
    c.is_archived = body.is_archived

    action_name = "CASE_ARCHIVE" if body.is_archived else "CASE_UNARCHIVE"
    db.add(AuditLog(
        user_id=current_admin.id,
        case_id=c.id,
        action=action_name,
        resource=f"case:{c.id}",
        details={"is_archived": body.is_archived}
    ))

    db.commit()
    db.refresh(c)
    return to_admin_case_response(c, db)
