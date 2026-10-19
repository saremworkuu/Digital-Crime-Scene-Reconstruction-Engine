from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status,Request
from sqlalchemy.orm import Session
from uuid import UUID

from sqlalchemy import or_

from app.core.dependencies import get_current_user
from app.db.session import get_db
from app.db.models.case import Case
from app.db.models.user import User, UserRole
from app.db.models.audit_log import AuditLog
from app.schemas.case import CaseCreate, CaseResponse, CaseUpdate
from app.db.models.case_assignment import CaseAssignment
from app.schemas.case import (
    CaseAssignmentCreate,
    CaseAssignmentResponse,
)
from app.services.audit import log_audit_event
router = APIRouter()


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
    # Only Admins and Investigators may create cases.
    if current_user.role not in (UserRole.ADMIN, UserRole.INVESTIGATOR):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Admins and Investigators can create cases.",
        )

    # Build the case using trusted server-side values.
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

        # Record who created the case.
        audit_entry = log_audit_event(
            db=db,
            user=current_user,
            action="case.created",
            resource=f"case:{new_case.id}",
            request=request,
            case_id=new_case.id,
            details={
                "case_name": new_case.name,
                "status": (new_case.status.value
                if hasattr(new_case.status, "value")
                else str(new_case.status),
                )
            },
        )
    
        db.commit()
        db.refresh(new_case)

    except Exception:
        db.rollback()
        raise

    return new_case



@router.get("/", response_model=list[CaseResponse])
def list_cases(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Hide soft-deleted cases from ordinary listings.
    query = db.query(Case).filter(Case.is_deleted.is_(False))

    # Admins can see every non-deleted case.
    if current_user.role == UserRole.ADMIN:
        pass

    # Investigators can see cases they created or were assigned.
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

    # Viewers can see only cases assigned to them.
    elif current_user.role == UserRole.VIEWER:
        assigned_case_ids = (
            db.query(CaseAssignment.case_id)
            .filter(CaseAssignment.user_id == current_user.id)
        )

        query = query.filter(Case.id.in_(assigned_case_ids))

    else:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to view cases.",
        )

    return query.order_by(Case.created_at.desc()).all()



@router.post(
    "/{case_id}/assignments",
    response_model=CaseAssignmentResponse,
    status_code=status.HTTP_201_CREATED,
)
def assign_case(
    request: Request,
    case_id: UUID,
    assignment_data: CaseAssignmentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Only admins can assign cases.
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=403,
            detail="Only admins can assign cases.",
        )

    # Make sure the case exists and is not deleted.
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

    # Find the user who will receive the assignment.
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

    if assigned_user.role not in (
        UserRole.INVESTIGATOR,
        UserRole.VIEWER,
    ):
        raise HTTPException(
            status_code=400,
            detail="Cases can only be assigned to investigators or viewers.",
        )

    # Prevent duplicate assignments.
    existing = (
        db.query(CaseAssignment)
        .filter(
            CaseAssignment.case_id == case_id,
            CaseAssignment.user_id == assigned_user.id,
        )
        .first()
    )

    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="This user is already assigned to the case.",
        )

    assignment = CaseAssignment(
        case_id=case_id,
        user_id=assigned_user.id,
        assigned_by=current_user.id,
    )

    try:
        db.add(assignment)
        db.flush()

        audit_entry = log_audit_event(
            db=db,
            user=current_user,
            action="case.assigned",
            resource=f"case:{case.id}",
            request=request,
            case_id=case.id,
            details={
            "case_name": case.name,
            "assigned_user_id": str(assigned_user.id),
            "assigned_user_role": assigned_user.role.value
            if hasattr(assigned_user.role, "value")
            else str(assigned_user.role),
        },
        )
        

        db.commit()
        db.refresh(assignment)
    except Exception:
        db.rollback()
        raise

    return assignment



@router.get("/{case_id}", response_model=CaseResponse)
def get_case(
    case_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Find the case, excluding soft-deleted records.
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

    # Admins can view all non-deleted cases.
    if current_user.role == UserRole.ADMIN:
        return case

    # Investigators can view cases they created or were assigned.
    if current_user.role == UserRole.INVESTIGATOR:
        if case.created_by == current_user.id:
            return case

        assignment = (
            db.query(CaseAssignment)
            .filter(
                CaseAssignment.case_id == case.id,
                CaseAssignment.user_id == current_user.id,
            )
            .first()
        )

        if assignment is not None:
            return case

    # Viewers can view cases assigned to them.
    elif current_user.role == UserRole.VIEWER:
        assignment = (
            db.query(CaseAssignment)
            .filter(
                CaseAssignment.case_id == case.id,
                CaseAssignment.user_id == current_user.id,
            )
            .first()
        )

        if assignment is not None:
            return case

    raise HTTPException(
        status_code=403,
        detail="You do not have permission to view this case.",
    )



@router.patch("/{case_id}", response_model=CaseResponse)
def update_case(
    request:Request,
    case_id: UUID,
    case_data: CaseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Find the case, excluding soft-deleted records.
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

    # Viewers cannot modify cases.
    if current_user.role == UserRole.VIEWER:
        raise HTTPException(
            status_code=403,
            detail="Viewers cannot update cases.",
        )

    # Admins can update any case.
    if current_user.role == UserRole.ADMIN:
        pass

    # Investigators can update cases they created or were assigned.
    elif current_user.role == UserRole.INVESTIGATOR:
        is_creator = case.created_by == current_user.id

        is_assigned = (
            db.query(CaseAssignment)
            .filter(
                CaseAssignment.case_id == case.id,
                CaseAssignment.user_id == current_user.id,
            )
            .first()
            is not None
        )

        if not is_creator and not is_assigned:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to update this case.",
            )

    else:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to update cases.",
        )

    # Get only fields explicitly included in the request.
    updates = case_data.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(
            status_code=422,
            detail="Provide at least one field to update.",
        )

    # Validate the case name if it was provided.
    if "name" in updates:
        if updates["name"] is None or not updates["name"].strip():
            raise HTTPException(
                status_code=422,
                detail="Case name cannot be empty.",
            )

        updates["name"] = updates["name"].strip()

    # Status must not be null.
    if "status" in updates and updates["status"] is None:
        raise HTTPException(
            status_code=422,
            detail="Case status cannot be null.",
        )

    try:
        for field, value in updates.items():
            setattr(case, field, value)

        audit_entry = log_audit_event(
            db=db,
            user=current_user,
            action="case.updated",
            resource=f"case:{case.id}",
            request=request,
            case_id=case.id,
            details={
                "case_name": case.name,
                "status": case.status.value
                if hasattr(case.status, "value")
                else str(case.status),
            },
        )

        db.commit()
        db.refresh(case)

    except Exception:
        db.rollback()
        raise

    return case



@router.delete("/{case_id}")
def delete_case(
    request:Request,
    case_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Find the case, excluding already deleted cases.
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

    # Viewers cannot delete cases.
    if current_user.role == UserRole.VIEWER:
        raise HTTPException(
            status_code=403,
            detail="Viewers cannot delete cases.",
        )

    # Admins can delete any non-deleted case.
    if current_user.role == UserRole.ADMIN:
        pass

    # Investigators can delete cases they created or were assigned.
    elif current_user.role == UserRole.INVESTIGATOR:
        is_creator = case.created_by == current_user.id

        is_assigned = (
            db.query(CaseAssignment)
            .filter(
                CaseAssignment.case_id == case.id,
                CaseAssignment.user_id == current_user.id,
            )
            .first()
            is not None
        )

        if not is_creator and not is_assigned:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to delete this case.",
            )

    else:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to delete cases.",
        )

    try:
        # Mark the case as deleted; do not remove the database row.
        case.is_deleted = True
        case.deleted_at = datetime.now(timezone.utc)

        audit_entry =log_audit_event(
            db=db,
            user=current_user,
            action="case.deleted",
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

    except Exception:
        db.rollback()
        raise

    return {
        "message": "Case deleted successfully.",
        "case_id": str(case.id),
    }
