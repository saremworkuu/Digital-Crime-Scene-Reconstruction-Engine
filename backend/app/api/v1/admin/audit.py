import math
import uuid
from datetime import datetime
from typing import Dict, Optional

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.permissions import require_admin
from app.db.models.audit_log import AuditLog
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.admin import (
    AdminAuditCreateRequest,
    AdminAuditEntryResponse,
)
from app.services.audit import (
    normalize_audit_action,
    normalize_audit_details_for_display,
    normalize_audit_timestamp,
    utc_now,
)

router = APIRouter(dependencies=[Depends(require_admin)])


def to_admin_audit_response(a: AuditLog, user_map: Dict[str, User]) -> AdminAuditEntryResponse:
    u = user_map.get(str(a.user_id))
    u_name = u.username if u else "System"
    role_val = (u.role.value if hasattr(u.role, "value") else str(u.role)) if u else "system"

    ts_utc = normalize_audit_timestamp(a.timestamp)
    ts_str = ts_utc.isoformat()
    canon_action = normalize_audit_action(a.action)
    norm_details = normalize_audit_details_for_display(canon_action, a.details)

    target_type = "SYSTEM"
    target_id = "global"
    if a.resource and ":" in a.resource:
        parts = a.resource.split(":", 1)
        target_type = parts[0].upper()
        target_id = parts[1]
    elif a.resource:
        target_type = a.resource.upper()

    return AdminAuditEntryResponse(
        id=str(a.id),
        timestamp=ts_str,
        user_id=str(a.user_id),
        user_name=u_name,
        role=role_val,
        action=canon_action,
        case_id=str(a.case_id) if a.case_id else None,
        target_type=target_type,
        target_id=target_id,
        details=norm_details if isinstance(norm_details, dict) else {"details": norm_details},
        ip_address=a.ip_address or "-",
    )


@router.get("")
@router.get("/")
def get_admin_audit_logs(
    user: Optional[str] = None,
    action: Optional[str] = None,
    case_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 15,
    db: Session = Depends(get_db),
):
    safe_page = max(1, page)
    safe_limit = max(1, min(limit, 200))

    filters = []
    users_by_id: Dict[str, User] = {}
    if user and user != "all":
        users = db.execute(select(User)).scalars().all()
        users_by_id = {str(u.id): u for u in users}
        matched_ids = []
        try:
            matched_ids.append(uuid.UUID(user))
        except Exception:
            pass
        for u_obj in users:
            if u_obj.username.lower() == user.lower() or str(u_obj.id) == user:
                matched_ids.append(u_obj.id)
        if not matched_ids:
            return {"entries": [], "total": 0, "page": safe_page, "totalPages": 1}
        filters.append(AuditLog.user_id.in_(matched_ids))

    if case_id and case_id != "all":
        try:
            filters.append(AuditLog.case_id == uuid.UUID(case_id))
        except Exception:
            return {"entries": [], "total": 0, "page": safe_page, "totalPages": 1}

    dt_from = None
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from.replace("Z", "+00:00"))
        except Exception:
            dt_from = None

    dt_to = None
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to.replace("Z", "+00:00"))
        except Exception:
            dt_to = None

    # Fast SQL pagination when neither canonical action filtering nor full-JSON search is requested
    has_action_filter = bool(action and action != "all")
    has_search_filter = bool(search and search.strip())

    if not has_action_filter and not has_search_filter and dt_from is None and dt_to is None:
        offset = (safe_page - 1) * safe_limit
        count_sub = select(func.count(AuditLog.id))
        for cond in filters:
            count_sub = count_sub.where(cond)

        total_val = int(db.execute(count_sub).scalar() or 0)
        if total_val == 0:
            return {"entries": [], "total": 0, "page": safe_page, "totalPages": 1}

        list_q = select(AuditLog, User).outerjoin(User, AuditLog.user_id == User.id)
        for cond in filters:
            list_q = list_q.where(cond)

        rows = db.execute(
            list_q.order_by(AuditLog.timestamp.desc()).offset(offset).limit(safe_limit)
        ).all()

        local_user_map: Dict[str, User] = {
            str(u_obj.id): u_obj for _, u_obj in rows if u_obj is not None
        }
        return {
            "entries": [to_admin_audit_response(a, local_user_map) for a, _ in rows],
            "total": total_val,
            "page": safe_page,
            "totalPages": math.ceil(total_val / safe_limit) if total_val > 0 else 1,
        }

    # Filtered path (pre-filtered by SQL user/case_id and joined with User in one query)
    list_q = select(AuditLog, User).outerjoin(User, AuditLog.user_id == User.id)
    for cond in filters:
        list_q = list_q.where(cond)
    rows = db.execute(list_q.order_by(AuditLog.timestamp.desc())).all()
    if not users_by_id:
        users_by_id = {str(u_obj.id): u_obj for _, u_obj in rows if u_obj is not None}

    canon_target_action = normalize_audit_action(action).lower() if has_action_filter and action else None
    search_q = search.lower().strip() if has_search_filter and search else None

    filtered = []
    for a, _ in rows:
        ts_utc = normalize_audit_timestamp(a.timestamp)
        if dt_from is not None and ts_utc < dt_from:
            continue
        if dt_to is not None and ts_utc > dt_to:
            continue

        resp = to_admin_audit_response(a, users_by_id)
        if canon_target_action and resp.action.lower() != canon_target_action:
            continue

        if search_q:
            details_str = str(resp.details).lower()
            if (
                search_q not in resp.action.lower()
                and search_q not in resp.user_name.lower()
                and search_q not in resp.target_id.lower()
                and search_q not in resp.ip_address.lower()
                and search_q not in details_str
            ):
                continue

        filtered.append(resp)

    total = len(filtered)
    start_idx = (safe_page - 1) * safe_limit
    paginated = filtered[start_idx : start_idx + safe_limit]

    return {
        "entries": paginated,
        "total": total,
        "page": safe_page,
        "totalPages": math.ceil(total / safe_limit) if total > 0 else 1,
    }


@router.post("/", response_model=AdminAuditEntryResponse, status_code=status.HTTP_201_CREATED)
def append_audit_entry(
    body: AdminAuditCreateRequest,
    request: Request,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    case_uuid = None
    if body.case_id:
        try:
            case_uuid = uuid.UUID(body.case_id)
        except Exception:
            pass

    resource_str = f"{body.target_type.lower()}:{body.target_id}"
    client_ip = request.client.host if request and request.client else "127.0.0.1"

    new_log = AuditLog(
        id=uuid.uuid4(),
        user_id=current_admin.id,
        case_id=case_uuid,
        action=normalize_audit_action(body.action),
        resource=resource_str,
        ip_address=client_ip,
        details=normalize_audit_details_for_display(normalize_audit_action(body.action), body.details or {}),
        timestamp=utc_now(),
    )
    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    user_map = {str(current_admin.id): current_admin}
    return to_admin_audit_response(new_log, user_map)
