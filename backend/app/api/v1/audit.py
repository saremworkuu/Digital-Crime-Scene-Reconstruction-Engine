from datetime import datetime
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.models.audit_log import AuditLog
from app.db.models.user import User, UserRole
from app.db.session import get_db
from app.schemas.audit import AuditLogResponse

router = APIRouter()


@router.get("/", response_model=list[AuditLogResponse])
def list_audit_logs(
    action: str | None = None,
    user_id: uuid.UUID | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Only Admins and Investigators may view audit logs.
    if current_user.role not in (
        UserRole.ADMIN,
        UserRole.INVESTIGATOR,
    ):
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

    if start_date:
        statement = statement.where(
            AuditLog.timestamp >= start_date
        )

    if end_date:
        statement = statement.where(
            AuditLog.timestamp <= end_date
        )

    statement = (
        statement
        .order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
    )

    logs = db.execute(statement).scalars().all()
    return logs
