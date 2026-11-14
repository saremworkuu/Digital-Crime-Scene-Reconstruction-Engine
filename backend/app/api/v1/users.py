from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.permissions import require_admin
from app.core.dependencies import get_current_user
from app.db.models.user import User

from uuid import UUID

from fastapi import HTTPException, status
from app.schemas.user import UserUpdate
from app.schemas.auth import UpdateProfileRequest
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


@router.get("/me")
def get_my_profile(
    current_user: User = Depends(get_current_user),
):
    role_str = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    dept = getattr(current_user, "department", None) or "Digital Forensic Incident Response (DFIR) Command"
    badge = getattr(current_user, "badge_id", None) or getattr(current_user, "badgeId", None) or ("ADMIN-001" if role_str == "admin" else "DFIR-4821")
    return {
        "id": str(current_user.id),
        "username": current_user.username,
        "name": current_user.username,
        "email": current_user.email,
        "role": role_str,
        "is_active": current_user.is_active,
        "department": dept,
        "badge_id": badge,
        "badgeId": badge,
        "created_at": current_user.created_at,
    }


@router.put("/me")
@router.patch("/me")
def update_my_profile(
    data: UpdateProfileRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    updates = data.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide at least one field to update.",
        )

    new_username = updates.get("username") or updates.get("name")
    if new_username:
        new_username = new_username.strip()
        if len(new_username) < 2:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Name must be at least 2 characters.",
            )
        current_user.username = new_username

    new_email = updates.get("email")
    if new_email:
        current_user.email = new_email.strip().lower()

    if "department" in updates and updates["department"] is not None:
        current_user.department = updates["department"].strip()

    badge = updates.get("badge_id") or updates.get("badgeId")
    if badge:
        if hasattr(current_user, "badge_id"):
            current_user.badge_id = badge.strip()
        elif hasattr(current_user, "badgeId"):
            current_user.badgeId = badge.strip()

    db.commit()
    db.refresh(current_user)

    role_str = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    dept = getattr(current_user, "department", None) or "Digital Forensic Incident Response (DFIR) Command"
    b = getattr(current_user, "badge_id", None) or getattr(current_user, "badgeId", None) or ("ADMIN-001" if role_str == "admin" else "DFIR-4821")
    return {
        "id": str(current_user.id),
        "username": current_user.username,
        "name": current_user.username,
        "email": current_user.email,
        "role": role_str,
        "is_active": current_user.is_active,
        "department": dept,
        "badge_id": b,
        "badgeId": b,
        "created_at": current_user.created_at,
    }


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
