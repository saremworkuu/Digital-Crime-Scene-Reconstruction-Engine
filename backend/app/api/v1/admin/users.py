import uuid
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.permissions import require_admin
from app.core.security import hash_password
from app.db.models.audit_log import AuditLog
from app.db.models.login_attempt import LoginAttempt
from app.db.models.user import User, UserRole
from app.db.session import get_db
from app.schemas.admin import (
    AdminUserCreateRequest,
    AdminUserResponse,
    AdminUserSession,
    AdminUserUpdateRequest,
)
from app.services.audit import log_audit_event, normalize_audit_timestamp

router = APIRouter(dependencies=[Depends(require_admin)])


def to_admin_user_response(
    u: User,
    *,
    failed_attempts_by_email: Optional[Dict[str, int]] = None,
    last_login_by_user: Optional[Dict[uuid.UUID, str]] = None,
) -> AdminUserResponse:
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
            ip=s.get("ip", "-"),
            last_active=s.get("last_active", "Recently"),
        )
        for idx, s in enumerate(sessions_list)
    ]

    last_active = (
        sessions_list[0].get("last_active", "Never")
        if sessions_list
        else (last_login_by_user.get(u.id, "Never") if last_login_by_user is not None else "Never")
    )
    failed_count = (
        failed_attempts_by_email.get((u.email or "").lower(), 0)
        if failed_attempts_by_email is not None
        else 0
    )

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
        failed_login_attempts=failed_count,
        sessions=sessions,
    )


def _get_user_telemetry_maps(db: Session, user_ids: List[uuid.UUID], emails: List[str]):
    failed_map: Dict[str, int] = {}
    if emails:
        for email_val, cnt in db.execute(
            select(func.lower(LoginAttempt.email), func.count(LoginAttempt.id))
            .where(func.lower(LoginAttempt.email).in_([e.lower() for e in emails]))
            .group_by(func.lower(LoginAttempt.email))
        ).all():
            if email_val:
                failed_map[str(email_val).lower()] = int(cnt or 0)

    last_login_map: Dict[uuid.UUID, str] = {}
    if user_ids:
        for uid, ts in db.execute(
            select(AuditLog.user_id, func.max(AuditLog.timestamp))
            .where(
                AuditLog.user_id.in_(user_ids),
                AuditLog.action.in_(["user.login", "auth.login", "USER_LOGIN"]),
            )
            .group_by(AuditLog.user_id)
        ).all():
            if ts is not None:
                last_login_map[uid] = normalize_audit_timestamp(ts).isoformat()

    return failed_map, last_login_map


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
    if not users:
        return []

    failed_map, last_login_map = _get_user_telemetry_maps(
        db,
        [u.id for u in users],
        [u.email for u in users if u.email],
    )

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

        result.append(
            to_admin_user_response(
                u,
                failed_attempts_by_email=failed_map,
                last_login_by_user=last_login_map,
            )
        )

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

    failed_map, last_login_map = _get_user_telemetry_maps(db, [u.id], [u.email] if u.email else [])
    return to_admin_user_response(
        u,
        failed_attempts_by_email=failed_map,
        last_login_by_user=last_login_map,
    )


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

    pwd = data.password or f"DCSRE@{uuid.uuid4().hex[:10]}!"
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
        sessions=[],
    )
    db.add(new_user)

    log_audit_event(
        db=db,
        user=current_admin,
        action="user.created",
        resource=f"user:{new_user.id}",
        details={"name": new_user.username, "email": new_user.email, "role": data.role, "department": data.department},
    )

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

    log_audit_event(
        db=db,
        user=current_admin,
        action="user.updated",
        resource=f"user:{u.id}",
        details=details,
    )

    db.commit()
    db.refresh(u)
    failed_map, last_login_map = _get_user_telemetry_maps(db, [u.id], [u.email] if u.email else [])
    return to_admin_user_response(u, failed_attempts_by_email=failed_map, last_login_by_user=last_login_map)


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

    log_audit_event(
        db=db,
        user=current_admin,
        action="user.deleted",
        resource=f"user:{user_id}",
        details=deleted_info,
    )

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

    log_audit_event(
        db=db,
        user=current_admin,
        action="user.password_reset",
        resource=f"user:{u.id}",
        details={"reset_initiated_by": "admin", "token_generated": True},
    )

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

    log_audit_event(
        db=db,
        user=current_admin,
        action="session.terminated",
        resource=f"user:{u.id}",
        details={"terminated_session_id": session_id},
    )

    db.commit()
    return {"message": f"Session {session_id} terminated."}
