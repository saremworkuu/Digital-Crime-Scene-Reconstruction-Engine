# Audit service

import json
import uuid

from fastapi import Request
from sqlalchemy.orm import Session

from app.db.models.audit_log import AuditLog
from app.db.models.user import User


def log_audit_event(
    db: Session,
    user: User,
    action: str,
    resource: str,
    request: Request | None = None,
    case_id: uuid.UUID | None = None,
    details: dict | list | str | None = None,
) -> AuditLog:
    ip_address = None
    user_agent = None

    if request is not None:
        if request.client is not None:
            ip_address = request.client.host

        user_agent = request.headers.get("user-agent")

    

    audit_entry = AuditLog(
        user_id=user.id,
        case_id=case_id,
        action=action,
        resource=resource,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details,
    )

    db.add(audit_entry)
    return audit_entry
