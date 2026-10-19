from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.permissions import require_admin
from app.db.models.user import User

from uuid import UUID

from fastapi import HTTPException, status
from app.schemas.user import UserUpdate
from app.db.session import get_db

import logging
from sqlalchemy.exc import IntegrityError

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/")
def list_users(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    result = db.execute(
        select(User).order_by(User.created_at)
    )

    users = result.scalars().all()

    return [
        {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "is_active": user.is_active,
            "created_at": user.created_at,
        }
        for user in users
    ]


@router.patch("/{user_id}")
def update_user(
    user_id: UUID,
    user_data: UserUpdate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    updates = user_data.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide at least one field to update",
        )

    if "username" in updates and updates["username"] is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Username cannot be null",
        )

    if "email" in updates and updates["email"] is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Email cannot be null",
        )

    if "role" in updates and updates["role"] is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Role cannot be null",
        )

    for field, value in updates.items():
        setattr(user, field, value)

    try:
        db.commit()
        db.refresh(user)

    except IntegrityError:
        db.rollback()
        logger.exception("Database integrity error while updating user")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Update conflicts with an existing database record.",
        )
    except Exception:
        db.rollback()
        logger.exception("Unexpected error while updating user")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while updating the user.",
        )

    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "is_active": user.is_active,
        "created_at": user.created_at,
    }


@router.patch("/{user_id}/status")
def update_user_status(
    user_id: UUID,
    is_active: bool,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user.id == current_user.id and not is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account.",
        )

    user.is_active = is_active

    db.commit()
    db.refresh(user)

    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "is_active": user.is_active,
    }
