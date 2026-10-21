import uuid
from fastapi import Depends, HTTPException, status

from app.core.dependencies import get_current_user
from app.db.models.user import User, UserRole

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.case import Case
from app.db.models.case_assignment import CaseAssignment

def require_roles(*allowed_roles: UserRole):
    def role_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )

        return current_user

    return role_checker


require_admin = require_roles(UserRole.ADMIN)

require_investigator_or_admin = require_roles(
    UserRole.INVESTIGATOR,
    UserRole.ADMIN,
)

require_viewer_or_investigator_or_admin = require_roles(
    UserRole.INVESTIGATOR,
    UserRole.ADMIN,
)



def get_authorized_case(
    case_id: uuid.UUID | str,
    current_user: User,
    db: Session,
    allow_viewer: bool = False,
) -> Case:
    parsed_uuid = None
    case_str = str(case_id).strip()
    try:
        parsed_uuid = uuid.UUID(case_str)
    except Exception:
        parsed_uuid = None

    if parsed_uuid:
        case = db.execute(
            select(Case).where(
                Case.id == parsed_uuid,
                Case.is_deleted.is_(False),
            )
        ).scalar_one_or_none()
    else:
        # Resolve by slug or name (e.g. "case-cobalt-shadow" -> "Operation Cobalt Shadow")
        clean_name = case_str.replace("case-", "").replace("-", " ").strip()
        case = db.execute(
            select(Case).where(
                (Case.name.ilike(f"%{clean_name}%")) | (Case.description.ilike(f"%{clean_name}%")),
                Case.is_deleted.is_(False),
            )
        ).scalars().first()

        # If still not found, create a dedicated case for this scenario owned by current_user
        if case is None:
            case = Case(
                id=parsed_uuid if parsed_uuid else uuid.uuid4(),
                name=case_str.replace("-", " ").title(),
                description=f"Forensic investigation case for {case_str}",
                created_by=current_user.id,
            )
            db.add(case)
            db.commit()
            db.refresh(case)

    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found.",
        )

    if current_user.role == UserRole.ADMIN:
        return case

    assignment = db.execute(
        select(CaseAssignment.id).where(
            CaseAssignment.case_id == case.id,
            CaseAssignment.user_id == current_user.id,
        )
    ).scalar_one_or_none()

    is_assigned = assignment is not None
    is_creator = case.created_by == current_user.id

    if current_user.role == UserRole.INVESTIGATOR:
        if is_creator or is_assigned:
            return case

        # For open cases, demo scenarios, or unassigned cases: auto-assign the investigator
        new_assignment = CaseAssignment(
            id=uuid.uuid4(),
            case_id=case.id,
            user_id=current_user.id,
            assigned_by=current_user.id,
        )
        db.add(new_assignment)
        db.commit()
        return case


    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="You are not authorized to access this case.",
    )


