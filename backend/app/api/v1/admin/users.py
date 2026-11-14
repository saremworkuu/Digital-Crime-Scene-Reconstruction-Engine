import uuid
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import select, func, or_

from app.core.permissions import require_admin
from app.core.security import hash_password
from app.db.session import get_db
from app.db.models.user import User, UserRole
from app.db.models.audit_log import AuditLog
from app.schemas.admin import (
    AdminUserResponse,
    AdminUserCreateRequest,
    AdminUserUpdateRequest,
    AdminUserSession,
)

router = APIRouter(dependencies=[Depends(require_admin)])


def to_admin_user_response(u: User) -> AdminUserResponse:
    role_str = u.role.value if hasattr(u.role, "value") else str(u.role)
    status_str = getattr(u, "status", None) or ("active" if u.is_active else "disabled")
    dept_str = getattr(u, "department", None) or "Digital Forensics"
    tfa_bool = getattr(u, "two_factor_enabled", False)
    sessions_list = getattr(u, "sessions", None) or []
    created_at_str = u.created_at.isoformat() if hasattr(u.created_at, "isoformat") else str(u.created_at)

    sessions = [
        AdminUserSession(
            id=s.get("id", f"sess-{idx}"),
            device=s.get("device", "Desktop Client"),
            ip=s.get("ip", "127.0.0.1"),
            last_active=s.get("last_active", "Recently")
        )
        for idx, s in enumerate(sessions_list)
    ]

    last_active = sessions_list[0].get("last_active", "Never") if sessions_list else "Never"

    return AdminUserResponse(
        id=str(u.id),
        name=u.username,
        email=u.email,
        role=role_str,
        status=status_str,
        last_login=last_active,
        department=dept_str,
        created_at=created_at_str,
        two_factor_enabled=bool(tfa_bool),
        failed_login_attempts=0,
        sessions=sessions,
    )


@router.get("", response_model=List[AdminUserResponse])
@router.get("/", response_model=List[AdminUserResponse])
def get_admin_users(
    role: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = select(User).order_by(User.created_at.desc())
    users = db.execute(query).scalars().all()

    result = []
    for u in users:
        role_val = u.role.value if hasattr(u.role, "value") else str(u.role)
        status_val = getattr(u, "status", None) or ("active" if u.is_active else "disabled")

        if role and role != "all" and role_val.lower() != role.lower():
            continue
        if status and status != "all" and status_val.lower() != status.lower():
            continue
        if search:
            q = search.lower()
            u_name = u.username.lower()
            u_email = u.email.lower()
            u_dept = (getattr(u, "department", "") or "").lower()
            if q not in u_name and q not in u_email and q not in u_dept:
                continue

        result.append(to_admin_user_response(u))

    return result


@router.get("/{user_id}", response_model=AdminUserResponse)
def get_admin_user_by_id(
    user_id: str,
    db: Session = Depends(get_db),
):
    try:
        user_uuid = uuid.UUID(user_id)
        u = db.get(User, user_uuid)
    except Exception:
        u = db.execute(select(User).where(User.username == user_id)).scalar_one_or_none()

    if not u:
        raise HTTPException(status_code=404, detail=f"User {user_id} not found.")

    return to_admin_user_response(u)


@router.post("/", response_model=AdminUserResponse, status_code=status.HTTP_201_CREATED)
def create_admin_user(
    data: AdminUserCreateRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    email_clean = data.email.lower().strip()
    existing = db.execute(
        select(User).where((User.email == email_clean) | (User.username == data.name))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="User with this email or username already exists.")

    try:
        role_enum = UserRole(data.role.lower())
    except Exception:
        role_enum = UserRole.INVESTIGATOR

    pwd = data.password or "DCSRE@Pass2026!"
    new_user = User(
        id=uuid.uuid4(),
        username=data.name,
        email=email_clean,
        hashed_password=hash_password(pwd),
        role=role_enum,
        is_active=(data.status == "active"),
        department=data.department,
        status=data.status or "active",
        two_factor_enabled=False,
        sessions=[]
    )
    db.add(new_user)

    # Log audit entry
    db.add(AuditLog(
        user_id=current_admin.id,
        action="USER_CREATE",
        resource=f"user:{new_user.id}",
        details={"name": new_user.username, "email": new_user.email, "role": data.role, "department": data.department}
    ))

    db.commit()
    db.refresh(new_user)
    return to_admin_user_response(new_user)


@router.patch("/{user_id}", response_model=AdminUserResponse)
def update_admin_user(
    user_id: str,
    patch: AdminUserUpdateRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        user_uuid = uuid.UUID(user_id)
        u = db.get(User, user_uuid)
    except Exception:
        u = db.execute(select(User).where(User.username == user_id)).scalar_one_or_none()

    if not u:
        raise HTTPException(status_code=404, detail=f"User {user_id} not found.")

    details = {}
    if patch.name is not None:
        u.username = patch.name
        details["name"] = patch.name
    if patch.email is not None:
        u.email = patch.email.lower().strip()
        details["email"] = patch.email
    if patch.role is not None:
        try:
            u.role = UserRole(patch.role.lower())
            details["role"] = patch.role
        except Exception:
            pass
    if patch.department is not None:
        u.department = patch.department
        details["department"] = patch.department
    if patch.status is not None:
        u.status = patch.status
        u.is_active = (patch.status == "active")
        details["status"] = patch.status
    if patch.two_factor_enabled is not None:
        u.two_factor_enabled = patch.two_factor_enabled
        details["two_factor_enabled"] = patch.two_factor_enabled

    db.add(AuditLog(
        user_id=current_admin.id,
        action="USER_UPDATE",
        resource=f"user:{u.id}",
        details=details
    ))

    db.commit()
    db.refresh(u)
    return to_admin_user_response(u)


@router.delete("/{user_id}")
def delete_admin_user(
    user_id: str,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        user_uuid = uuid.UUID(user_id)
        u = db.get(User, user_uuid)
    except Exception:
        u = db.execute(select(User).where(User.username == user_id)).scalar_one_or_none()

    if not u:
        raise HTTPException(status_code=404, detail=f"User {user_id} not found.")

    if u.id == current_admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own administrator account.")

    deleted_info = {"name": u.username, "email": u.email}
    db.delete(u)

    db.add(AuditLog(
        user_id=current_admin.id,
        action="USER_DELETE",
        resource=f"user:{user_id}",
        details=deleted_info
    ))

    db.commit()
    return {"message": "User deleted successfully", "id": user_id}


@router.post("/{user_id}/reset-password")
def reset_admin_user_password(
    user_id: str,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        user_uuid = uuid.UUID(user_id)
        u = db.get(User, user_uuid)
    except Exception:
        u = db.execute(select(User).where(User.username == user_id)).scalar_one_or_none()

    if not u:
        raise HTTPException(status_code=404, detail=f"User {user_id} not found.")

    token = f"TMP-PWD-{uuid.uuid4().hex[:7].upper()}"
    u.hashed_password = hash_password(token)

    db.add(AuditLog(
        user_id=current_admin.id,
        action="USER_PASSWORD_RESET",
        resource=f"user:{u.id}",
        details={"reset_initiated_by": "admin", "token_generated": True}
    ))

    db.commit()
    return {"temporaryToken": token}


@router.post("/{user_id}/sessions/{session_id}/terminate")
def terminate_user_session(
    user_id: str,
    session_id: str,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        user_uuid = uuid.UUID(user_id)
        u = db.get(User, user_uuid)
    except Exception:
        u = db.execute(select(User).where(User.username == user_id)).scalar_one_or_none()

    if not u:
        raise HTTPException(status_code=404, detail=f"User {user_id} not found.")

    current_sessions = getattr(u, "sessions", []) or []
    u.sessions = [s for s in current_sessions if s.get("id") != session_id]

    db.add(AuditLog(
        user_id=current_admin.id,
        action="SESSION_TERMINATED",
        resource=f"user:{u.id}",
        details={"terminated_session_id": session_id}
    ))

    db.commit()
    return {"message": f"Session {session_id} terminated."}
