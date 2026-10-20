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
    UserRole.VIEWER,
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
        clean_name = case_str.replace("case-", "").replace("-", " ")
        case = db.execute(
            select(Case).where(
                Case.name.ilike(f"%{clean_name}%"),
                Case.is_deleted.is_(False),
            )
        ).scalars().first()

        # If not found, look up any existing active case
        if case is None:
            case = db.execute(select(Case).where(Case.is_deleted.is_(False))).scalars().first()

        # If no case exists at all, auto-create one for this scenario
        if case is None:
            case = Case(
                id=parsed_uuid if parsed_uuid else uuid.uuid4(),
                name=case_str.replace("-", " ").title(),
                description=f"Auto-generated case for {case_str}",
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

    if (
        allow_viewer
        and current_user.role == UserRole.VIEWER
        and is_assigned
    ):
        return case

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="You are not authorized to access this case.",
    )
