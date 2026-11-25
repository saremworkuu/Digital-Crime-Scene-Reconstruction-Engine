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
from app.services.audit import (
    matching_raw_actions,
    normalize_audit_action,
    normalize_audit_details_for_display,
    normalize_audit_timestamp,
    utc_now,
)

router = APIRouter()


def _sorted_audit_rows(rows: list[tuple[AuditLog, str | None, UserRole | str | None]]):
    """Sort audit rows by UTC timestamp descending, breaking ties by insertion order."""
    return [
        row
        for _, row in sorted(
            enumerate(rows),
            key=lambda pair: (-normalize_audit_timestamp(pair[1][0].timestamp).timestamp(), pair[0]),
        )
    ]


def _serialize_audit_row(log: AuditLog, username: str | None, role: UserRole | str | None) -> dict:
    canonical_action = normalize_audit_action(log.action)
    display_details = normalize_audit_details_for_display(canonical_action, log.details)
    return {
        "id": log.id,
        "user_id": log.user_id,
        "case_id": log.case_id,
        "action": canonical_action,
        "resource": log.resource,
        "ip_address": log.ip_address,
        "user_agent": log.user_agent,
        "details": display_details,
        "timestamp": normalize_audit_timestamp(log.timestamp),
        "user_name": username,
        "user_role": role.value if hasattr(role, "value") else role,
        "target_type": (log.resource or "system").split(":", 1)[0],
        "target_id": ((log.resource or "").split(":", 1)[1] if ":" in (log.resource or "") else str(log.id)),
    }


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

    if start_date and end_date and normalize_audit_timestamp(start_date) > normalize_audit_timestamp(end_date):
        raise HTTPException(
            status_code=400,
            detail="start_date cannot be later than end_date.",
        )

    statement = select(AuditLog, User.username, User.role).outerjoin(User, User.id == AuditLog.user_id)

    if action:
        statement = statement.where(AuditLog.action.in_(matching_raw_actions(action)))

    if user_id:
        statement = statement.where(AuditLog.user_id == user_id)

    if case_id:
        statement = statement.where(AuditLog.case_id == case_id)

    rows = db.execute(statement).all()

    start_utc = normalize_audit_timestamp(start_date) if start_date else None
    end_utc = normalize_audit_timestamp(end_date) if end_date else None
    if start_utc or end_utc:
        filtered_rows = []
        for row in rows:
            ts = normalize_audit_timestamp(row[0].timestamp)
            if start_utc and ts < start_utc:
                continue
            if end_utc and ts > end_utc:
                continue
            filtered_rows.append(row)
        rows = filtered_rows

    sorted_rows = _sorted_audit_rows(rows)[offset : offset + limit]
    return [_serialize_audit_row(log, username, role) for log, username, role in sorted_rows]


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

    rows = _sorted_audit_rows(db.execute(statement).all())

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
        item = _serialize_audit_row(log, username, role)
        writer.writerow([
            str(item["id"]),
            item["timestamp"].isoformat(),
            str(item["user_id"]) if item["user_id"] else "",
            item["user_name"] or "",
            item["user_role"] or "",
            item["action"] or "",
            item["target_type"],
            item["target_id"],
            item["ip_address"] or "",
            json.dumps(item["details"] or {}),
        ])

    filename = f"dcsre_audit_trail_{utc_now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )
