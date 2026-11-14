import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import math
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc

from app.core.permissions import require_admin
from app.db.session import get_db
from app.db.models.audit_log import AuditLog
from app.db.models.user import User
from app.schemas.admin import (
    AdminAuditEntryResponse,
    AdminAuditCreateRequest,
)

router = APIRouter(dependencies=[Depends(require_admin)])


def to_admin_audit_response(a: AuditLog, user_map: Dict[str, User]) -> AdminAuditEntryResponse:
    u = user_map.get(str(a.user_id))
    u_name = u.username if u else "Sarem Worku"
    role_val = (u.role.value if hasattr(u.role, "value") else str(u.role)) if u else "admin"

    ts_str = a.timestamp.isoformat() if hasattr(a.timestamp, "isoformat") else str(a.timestamp)

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
        action=a.action,
        case_id=str(a.case_id) if a.case_id else None,
        target_type=target_type,
        target_id=target_id,
        details=a.details if isinstance(a.details, dict) else {"details": a.details},
        ip_address=a.ip_address or "192.168.1.104",
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
    users = db.execute(select(User)).scalars().all()
    user_map = {str(u.id): u for u in users}

    query = select(AuditLog).order_by(desc(AuditLog.timestamp))
    items = db.execute(query).scalars().all()

    filtered = []
    for a in items:
        resp = to_admin_audit_response(a, user_map)

        if user and user != "all":
            if resp.user_id != user and resp.user_name.lower() != user.lower():
                continue

        if action and action != "all" and resp.action.lower() != action.lower():
            continue

        if case_id and case_id != "all":
            if not resp.case_id or resp.case_id != case_id:
                continue

        if date_from:
            try:
                if datetime.fromisoformat(resp.timestamp.replace("Z", "+00:00")) < datetime.fromisoformat(date_from.replace("Z", "+00:00")):
                    continue
            except Exception:
                pass

        if date_to:
            try:
                if datetime.fromisoformat(resp.timestamp.replace("Z", "+00:00")) > datetime.fromisoformat(date_to.replace("Z", "+00:00")):
                    continue
            except Exception:
                pass

        if search:
            q = search.lower()
            details_str = str(resp.details).lower()
            if (
                q not in resp.action.lower()
                and q not in resp.user_name.lower()
                and q not in resp.target_id.lower()
                and q not in resp.ip_address.lower()
                and q not in details_str
            ):
                continue

        filtered.append(resp)

    total = len(filtered)
    start_idx = (page - 1) * limit
    paginated = filtered[start_idx : start_idx + limit]

    return {
        "entries": paginated,
        "total": total,
        "page": page,
        "totalPages": math.ceil(total / limit) if total > 0 else 1,
    }


@router.post("/", response_model=AdminAuditEntryResponse, status_code=status.HTTP_201_CREATED)
def append_audit_entry(
    body: AdminAuditCreateRequest,
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

    new_log = AuditLog(
        id=uuid.uuid4(),
        user_id=current_admin.id,
        case_id=case_uuid,
        action=body.action,
        resource=resource_str,
        ip_address="192.168.1.104",
        details=body.details or {},
        timestamp=datetime.now(timezone.utc),
    )
    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    user_map = {str(current_admin.id): current_admin}
    return to_admin_audit_response(new_log, user_map)
