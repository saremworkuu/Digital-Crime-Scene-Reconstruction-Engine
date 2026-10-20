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

    statement = select(AuditLog)

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

    logs = db.execute(statement).scalars().all()
    return logs


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

    statement = select(AuditLog)
    if case_id:
        statement = statement.where(AuditLog.case_id == case_id)

    logs = db.execute(statement.order_by(AuditLog.timestamp.desc())).scalars().all()

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

    for log in logs:
        writer.writerow([
            str(log.id),
            log.timestamp.isoformat() if hasattr(log.timestamp, "isoformat") else str(log.timestamp),
            str(log.user_id) if log.user_id else "",
            log.user_name or "",
            log.user_role or "",
            log.action or "",
            log.target_type or "",
            log.target_id or "",
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
