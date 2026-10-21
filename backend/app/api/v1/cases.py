from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from uuid import UUID

from sqlalchemy import or_, func, select

from app.core.dependencies import get_current_user
from app.db.session import get_db
from app.db.models.case import Case, CaseStatus
from app.db.models.user import User, UserRole
from app.db.models.audit_log import AuditLog
from app.db.models.evidence import Evidence
from app.db.models.events import Event
from app.db.models.detection import Detection, DetectionSeverity
from app.db.models.case_assignment import CaseAssignment
from app.schemas.case import (
    CaseCreate,
    CaseResponse,
    CaseUpdate,
    CaseAssignmentCreate,
    CaseAssignmentResponse,
    CaseAssignMultipleRequest,
)
from app.services.audit import log_audit_event
from app.core.permissions import get_authorized_case

router = APIRouter()


def enrich_case_response(case: Case, db: Session) -> CaseResponse:
    """Computes real-time case telemetry (evidence, events, detections, assignees)."""
    ev_count = db.execute(
        select(func.count(Evidence.id)).where(Evidence.case_id == case.id)
    ).scalar() or 0

    evt_count = db.execute(
        select(func.count(Event.id)).where(Event.case_id == case.id)
    ).scalar() or 0

    det_count = db.execute(
        select(func.count(Detection.id)).where(Detection.case_id == case.id)
    ).scalar() or 0

    crit_det_count = db.execute(
        select(func.count(Detection.id)).where(
            Detection.case_id == case.id,
            Detection.severity == DetectionSeverity.CRITICAL,
        )
    ).scalar() or 0

    assigned_users = db.execute(
        select(User.username)
        .join(CaseAssignment, CaseAssignment.user_id == User.id)
        .where(CaseAssignment.case_id == case.id)
    ).scalars().all()

    owner = db.get(User, case.created_by)
    owner_name = owner.username if owner else "Lead Investigator"

    return CaseResponse(
        id=case.id,
        name=case.name,
        description=case.description,
        status=case.status,
        created_by=case.created_by,
        created_at=case.created_at,
        updated_at=case.updated_at,
        tags=["Incident", "DFIR", "Forensics"],
        evidence_count=ev_count,
        event_count=evt_count,
        detection_count=det_count,
        critical_detection_count=crit_det_count,
        assigned_users=list(assigned_users),
        owner_id=str(case.created_by),
        owner_name=owner_name,
    )


@router.post(
    "/",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_case(
    request: Request,
    case_data: CaseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in (UserRole.ADMIN, UserRole.INVESTIGATOR):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Admins and Investigators can create cases.",
        )

    new_case = Case(
        name=case_data.name.strip(),
        description=case_data.description,
        created_by=current_user.id,
    )

    if not new_case.name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Case name cannot be empty.",
        )

    try:
        db.add(new_case)
        db.flush()

        log_audit_event(
            db=db,
            user=current_user,
            action="case.created",
            resource=f"case:{new_case.id}",
            request=request,
            case_id=new_case.id,
            details={
                "case_name": new_case.name,
                "status": (
                    new_case.status.value
                    if hasattr(new_case.status, "value")
                    else str(new_case.status)
                ),
            },
        )

        db.commit()
        db.refresh(new_case)

    except Exception:
        db.rollback()
        raise

    return enrich_case_response(new_case, db)


@router.get("/", response_model=list[CaseResponse])
def list_cases(
    case_status: str | None = Query(default=None, alias="status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Case).filter(Case.is_deleted.is_(False))

    if current_user.role == UserRole.ADMIN:
        pass
    elif current_user.role == UserRole.INVESTIGATOR:
        assigned_case_ids = (
            db.query(CaseAssignment.case_id)
            .filter(CaseAssignment.user_id == current_user.id)
        )
        query = query.filter(
            or_(
                Case.created_by == current_user.id,
                Case.id.in_(assigned_case_ids),
            )
        )
    else:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to view cases.",
        )


    if case_status:
        normalized_status = case_status.lower().replace(" ", "_")
        try:
            status_enum = CaseStatus(normalized_status)
            query = query.filter(Case.status == status_enum)
        except ValueError:
            pass

    cases = query.order_by(Case.created_at.desc()).all()
    return [enrich_case_response(c, db) for c in cases]


@router.post(
    "/{case_id}/assignments",
    response_model=CaseAssignmentResponse,
    status_code=status.HTTP_201_CREATED,
)
def assign_case_single(
    request: Request,
    case_id: UUID,
    assignment_data: CaseAssignmentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=403,
            detail="Only admins can assign cases.",
        )

    case = (
        db.query(Case)
        .filter(
            Case.id == case_id,
            Case.is_deleted.is_(False),
        )
        .first()
    )

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Case not found.",
        )

    assigned_user = (
        db.query(User)
        .filter(User.id == assignment_data.user_id)
        .first()
    )

    if assigned_user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    existing = (
        db.query(CaseAssignment)
        .filter(
            CaseAssignment.case_id == case_id,
            CaseAssignment.user_id == assigned_user.id,
        )
        .first()
    )

    if existing is not None:
        return existing

    assignment = CaseAssignment(
        case_id=case_id,
        user_id=assigned_user.id,
        assigned_by=current_user.id,
    )

    try:
        db.add(assignment)
        db.flush()

        log_audit_event(
            db=db,
            user=current_user,
            action="case.assigned",
            resource=f"case:{case.id}",
            request=request,
            case_id=case.id,
            details={
                "case_name": case.name,
                "assigned_user_id": str(assigned_user.id),
                "assigned_user_role": (
                    assigned_user.role.value
                    if hasattr(assigned_user.role, "value")
                    else str(assigned_user.role)
                ),
            },
        )

        db.commit()
        db.refresh(assignment)
    except Exception:
        db.rollback()
        raise

    return assignment


@router.post(
    "/{case_id}/assign",
    response_model=CaseResponse,
)
def assign_case_multiple(
    request: Request,
    case_id: UUID,
    payload: CaseAssignMultipleRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != UserRole.ADMIN and current_user.role != UserRole.INVESTIGATOR:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to assign cases.",
        )

    case = (
        db.query(Case)
        .filter(
            Case.id == case_id,
            Case.is_deleted.is_(False),
        )
        .first()
    )

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Case not found.",
        )

    for uid in payload.user_ids:
        existing = (
            db.query(CaseAssignment)
            .filter(
                CaseAssignment.case_id == case_id,
                CaseAssignment.user_id == uid,
            )
            .first()
        )
        if not existing:
            db.add(CaseAssignment(case_id=case_id, user_id=uid, assigned_by=current_user.id))

    db.commit()
    db.refresh(case)
    return enrich_case_response(case, db)


@router.get("/{case_id}", response_model=CaseResponse)
def get_case(
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    case = get_authorized_case(
        case_id=case_id,
        current_user=current_user,
        db=db,
        allow_viewer=True,
    )
    return enrich_case_response(case, db)


@router.patch("/{case_id}", response_model=CaseResponse)
@router.put("/{case_id}", response_model=CaseResponse)
def update_case(
    request: Request,
    case_id: str,
    case_data: CaseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    case = get_authorized_case(
        case_id=case_id,
        current_user=current_user,
        db=db,
        allow_viewer=False,
    )

    updates = case_data.model_dump(exclude_unset=True)
    if "name" in updates and updates["name"]:
        case.name = updates["name"].strip()
    if "description" in updates:
        case.description = updates["description"]
    if "status" in updates and updates["status"]:
        case.status = updates["status"]

    try:
        log_audit_event(
            db=db,
            user=current_user,
            action="case.updated",
            resource=f"case:{case.id}",
            request=request,
            case_id=case.id,
            details={
                "case_name": case.name,
                "status": (
                    case.status.value
                    if hasattr(case.status, "value")
                    else str(case.status)
                ),
            },
        )
        db.commit()
        db.refresh(case)
    except Exception:
        db.rollback()
        raise

    return enrich_case_response(case, db)


@router.delete("/{case_id}")
def delete_case(
    request: Request,
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    case = get_authorized_case(
        case_id=case_id,
        current_user=current_user,
        db=db,
        allow_viewer=False,
    )

    try:
        case.is_deleted = True
        case.deleted_at = datetime.now(timezone.utc)

        log_audit_event(
            db=db,
            user=current_user,
            action="case.deleted",
            resource=f"case:{case.id}",
            request=request,
            case_id=case.id,
            details={"case_name": case.name},
        )
        db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "message": "Case deleted successfully.",
        "case_id": str(case.id),
    }


# Mount sub-resource routes under /cases/{case_id}/...
from app.api.v1.evidence import list_case_evidence, upload_case_evidence
from app.api.v1.events import get_case_events
from app.api.v1.timeline import get_case_timeline
from app.api.v1.graph import get_attack_graph
from app.api.v1.detections import get_case_detections, run_detection
from app.api.v1.reports import generate_report, export_html, export_pdf
from app.schemas.events import EventResponse
from app.schemas.detection import DetectionResponse
from app.schemas.graph import AttackGraphData

router.add_api_route("/{case_id}/evidence", list_case_evidence, methods=["GET"])
router.add_api_route("/{case_id}/evidence/upload", upload_case_evidence, methods=["POST"], status_code=status.HTTP_201_CREATED)
router.add_api_route("/{case_id}/evidence", upload_case_evidence, methods=["POST"], status_code=status.HTTP_201_CREATED)
router.add_api_route("/{case_id}/events", get_case_events, methods=["GET"], response_model=List[EventResponse])
router.add_api_route("/{case_id}/timeline", get_case_timeline, methods=["GET"], response_model=List[EventResponse])
router.add_api_route("/{case_id}/graph", get_attack_graph, methods=["GET"], response_model=AttackGraphData)
router.add_api_route("/{case_id}/detections", get_case_detections, methods=["GET"], response_model=List[DetectionResponse])
router.add_api_route("/{case_id}/run", run_detection, methods=["POST"], response_model=List[DetectionResponse])
router.add_api_route("/{case_id}/reports/generate", generate_report, methods=["POST"])
router.add_api_route("/{case_id}/reports/html", export_html, methods=["GET"])
router.add_api_route("/{case_id}/reports/pdf", export_pdf, methods=["GET"])

