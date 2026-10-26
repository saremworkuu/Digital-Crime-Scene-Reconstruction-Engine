from datetime import datetime
import uuid
import io
import csv
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.models.audit_log import AuditLog
from app.db.models.user import User, UserRole
from app.db.session import get_db
from app.schemas.audit import AuditLogResponse

router = APIRouter()


@router.get("", response_model=list[AuditLogResponse])
@router.get("/", response_model=list[AuditLogResponse])
@router.get("/logs", response_model=list[AuditLogResponse])
def list_audit_logs(
    action: Optional[str] = None,
    user_id: Optional[uuid.UUID] = None,
    case_id: Optional[uuid.UUID] = Query(None),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Only Admins and Investigators may view audit logs.
    if current_user.role not in (UserRole.ADMIN, UserRole.INVESTIGATOR):
        raise HTTPException(
            status_code=403,
            detail="You are not authorized to view audit logs.",
        )

    if start_date and end_date and start_date > end_date:
        raise HTTPException(
            status_code=400,
            detail="start_date cannot be later than end_date.",
        )

    statement = select(AuditLog, User.username, User.role).outerjoin(User, User.id == AuditLog.user_id)

    if action:
        statement = statement.where(AuditLog.action == action)

    if user_id:
        statement = statement.where(AuditLog.user_id == user_id)

    if case_id:
        statement = statement.where(AuditLog.case_id == case_id)

    if start_date:
        statement = statement.where(AuditLog.timestamp >= start_date)

    if end_date:
        statement = statement.where(AuditLog.timestamp <= end_date)

    statement = (
        statement
        .order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
    )

    rows = db.execute(statement).all()
    return [
        {
            "id": log.id, "user_id": log.user_id, "case_id": log.case_id,
            "action": log.action, "resource": log.resource,
            "ip_address": log.ip_address, "user_agent": log.user_agent,
            "details": log.details, "timestamp": log.timestamp,
            "user_name": username, "user_role": role.value if hasattr(role, "value") else role,
            "target_type": (log.resource or "system").split(":", 1)[0],
            "target_id": ((log.resource or "").split(":", 1)[1] if ":" in (log.resource or "") else str(log.id)),
        }
        for log, username, role in rows
    ]


@router.get("/export")
def export_audit_logs_csv(
    case_id: Optional[uuid.UUID] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role not in (UserRole.ADMIN, UserRole.INVESTIGATOR):
        raise HTTPException(
            status_code=403,
            detail="You are not authorized to export audit logs.",
        )

    statement = select(AuditLog, User.username, User.role).outerjoin(User, User.id == AuditLog.user_id)
    if case_id:
        statement = statement.where(AuditLog.case_id == case_id)

    rows = db.execute(statement.order_by(AuditLog.timestamp.desc())).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID",
        "Timestamp_UTC",
        "User_ID",
        "User_Name",
        "Role",
        "Action",
        "Target_Type",
        "Target_ID",
        "IP_Address",
        "Details_JSON",
    ])

    for log, username, role in rows:
        writer.writerow([
            str(log.id),
            log.timestamp.isoformat() if hasattr(log.timestamp, "isoformat") else str(log.timestamp),
            str(log.user_id) if log.user_id else "",
            username or "",
            role.value if hasattr(role, "value") else (role or ""),
            log.action or "",
            (log.resource or "system").split(":", 1)[0],
            (log.resource.split(":", 1)[1] if ":" in (log.resource or "") else str(log.id)),
            log.ip_address or "",
            json.dumps(log.details or {}),
        ])

    filename = f"dcsre_audit_trail_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )
