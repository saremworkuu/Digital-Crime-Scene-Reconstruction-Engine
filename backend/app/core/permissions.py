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
    case_id: uuid.UUID,
    current_user: User,
    db: Session,
    allow_viewer: bool = False,
) -> Case:
    case = db.execute(
        select(Case).where(
            Case.id == case_id,
            Case.is_deleted.is_(False),
        )
    ).scalar_one_or_none()

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
