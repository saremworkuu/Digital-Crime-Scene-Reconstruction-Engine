import uuid
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from app.core.permissions import require_admin
from app.db.models.case import Case, CaseStatus
from app.db.models.case_assignment import CaseAssignment
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.admin import (
    AdminCaseArchiveRequest,
    AdminCaseAssignRequest,
    AdminCaseLegalHoldRequest,
    AdminCaseResponse,
    AdminCaseStatusUpdateRequest,
)
from app.services.audit import log_audit_event

router = APIRouter(dependencies=[Depends(require_admin)])


def to_admin_case_response(
    c: Case,
    db: Session,
    *,
    artifact_counts: Optional[Dict[uuid.UUID, int]] = None,
    assigned_by_case: Optional[Dict[uuid.UUID, List[str]]] = None,
    owners_by_id: Optional[Dict[uuid.UUID, User]] = None,
) -> AdminCaseResponse:
    if artifact_counts is not None:
        ev_count = artifact_counts.get(c.id, 0)
    else:
        from app.api.v1.evidence import count_case_artifacts
        ev_count = count_case_artifacts(db, [c.id]).get(c.id, 0)

    if assigned_by_case is not None:
        assigned_names = assigned_by_case.get(c.id, [])
    else:
        assigned_names = list(
            db.execute(
                select(User.username)
                .join(CaseAssignment, CaseAssignment.user_id == User.id)
                .where(CaseAssignment.case_id == c.id)
            ).scalars().all()
        )

    owner_u = owners_by_id.get(c.created_by) if owners_by_id is not None else db.get(User, c.created_by)
    owner_name = owner_u.username if owner_u else "Unknown"

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

    clean = case_id.replace("case-", "").replace("-", " ").strip()
    c = db.execute(
        select(Case).where(
            (Case.name.ilike(f"%{clean}%")) | (Case.description.ilike(f"%{clean}%")),
            Case.is_deleted.is_(False),
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
    query = select(Case).where(Case.is_deleted.is_(False))
    if status and status != "all":
        try:
            query = query.where(Case.status == CaseStatus(status.lower()))
        except Exception:
            pass
    if archived is not None:
        query = query.where(Case.is_archived.is_(archived))
    query = query.order_by(Case.created_at.desc())

    cases = db.execute(query).scalars().all()
    if not cases:
        return []

    from app.api.v1.evidence import count_case_artifacts

    case_ids = [c.id for c in cases]
    artifact_counts = count_case_artifacts(db, case_ids)

    assigned_rows = db.execute(
        select(CaseAssignment.case_id, User.username)
        .join(User, CaseAssignment.user_id == User.id)
        .where(CaseAssignment.case_id.in_(case_ids))
    ).all()
    assigned_by_case: Dict[uuid.UUID, List[str]] = {}
    for cid, uname in assigned_rows:
        assigned_by_case.setdefault(cid, []).append(uname)

    owner_ids = list({c.created_by for c in cases if c.created_by})
    owners_by_id: Dict[uuid.UUID, User] = {}
    if owner_ids:
        for u in db.execute(select(User).where(User.id.in_(owner_ids))).scalars().all():
            owners_by_id[u.id] = u

    results = []
    search_q = search.lower().strip() if search else None
    for c in cases:
        resp = to_admin_case_response(
            c,
            db,
            artifact_counts=artifact_counts,
            assigned_by_case=assigned_by_case,
            owners_by_id=owners_by_id,
        )
        if status and status != "all" and resp.status.lower() != status.lower():
            continue
        if search_q:
            if (
                search_q not in resp.title.lower()
                and search_q not in resp.owner.lower()
                and search_q not in resp.description.lower()
                and not any(search_q in inv.lower() for inv in resp.assigned_investigators)
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

    log_audit_event(
        db=db,
        user=current_admin,
        case_id=c.id,
        action="case.status_changed",
        resource=f"case:{c.id}",
        details={"from": old_status, "to": body.status},
    )

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

    log_audit_event(
        db=db,
        user=current_admin,
        case_id=c.id,
        action="case.assigned",
        resource=f"case:{c.id}",
        details={"assigned_investigators": body.investigators},
    )

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

    action_name = "case.legal_hold_set" if body.legal_hold else "case.legal_hold_removed"
    log_audit_event(
        db=db,
        user=current_admin,
        case_id=c.id,
        action=action_name,
        resource=f"case:{c.id}",
        details={"legal_hold": body.legal_hold, "reason": body.reason or "Admin command directive"},
    )

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

    action_name = "case.archived" if body.is_archived else "case.unarchived"
    log_audit_event(
        db=db,
        user=current_admin,
        case_id=c.id,
        action=action_name,
        resource=f"case:{c.id}",
        details={"is_archived": body.is_archived},
    )

    db.commit()
    db.refresh(c)
    return to_admin_case_response(c, db)
