import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import math
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import select, func, or_

from app.core.permissions import require_admin
from app.db.session import get_db
from app.db.models.contact_message import ContactMessage
from app.db.models.user import User
from app.db.models.audit_log import AuditLog
from app.schemas.admin import (
    AdminContactMessageResponse,
    AdminReplyMessage,
    AdminMessageReplyRequest,
    AdminMessageStatusRequest,
    AdminMessagePriorityRequest,
    AdminMessageAssignRequest,
)

router = APIRouter(dependencies=[Depends(require_admin)])


def to_admin_message_response(m: ContactMessage) -> AdminContactMessageResponse:
    date_str = m.date.isoformat() if hasattr(m.date, "isoformat") else str(m.date)
    raw_replies = getattr(m, "reply_thread", None) or []
    replies = [
        AdminReplyMessage(
            id=r.get("id", f"rep-{idx}"),
            author=r.get("author", "Admin"),
            role=r.get("role", "Administrator"),
            message=r.get("message", ""),
            timestamp=r.get("timestamp", "")
        )
        for idx, r in enumerate(raw_replies)
    ]

    return AdminContactMessageResponse(
        id=m.id,
        reference=m.reference,
        sender_name=m.sender_name,
        sender_email=m.sender_email,
        sender_phone=m.sender_phone,
        subject=m.subject,
        category=m.category,
        status=m.status,
        priority=m.priority,
        assignee=m.assignee,
        date=date_str,
        is_read=m.is_read,
        body=m.body,
        reply_thread=replies,
    )


@router.get("")
@router.get("/")
def get_admin_messages(
    status: Optional[str] = None,
    category: Optional[str] = None,
    priority: Optional[str] = None,
    assignee: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 10,
    db: Session = Depends(get_db),
):
    query = select(ContactMessage).order_by(ContactMessage.date.desc())
    items = db.execute(query).scalars().all()

    unread_count = sum(1 for m in items if not m.is_read and m.status not in ("archived", "spam"))

    filtered = []
    for m in items:
        if status and status != "all" and m.status.lower() != status.lower():
            continue
        if category and category != "all" and m.category.lower() != category.lower():
            continue
        if priority and priority != "all" and m.priority.lower() != priority.lower():
            continue
        if assignee and assignee != "all":
            if assignee == "unassigned" and m.assignee is not None:
                continue
            if assignee != "unassigned" and m.assignee != assignee:
                continue
        if search:
            q = search.lower()
            if (
                q not in m.reference.lower()
                and q not in m.sender_name.lower()
                and q not in m.sender_email.lower()
                and q not in m.subject.lower()
                and q not in m.body.lower()
            ):
                continue

        filtered.append(to_admin_message_response(m))

    total = len(filtered)
    start_idx = (page - 1) * limit
    paginated = filtered[start_idx : start_idx + limit]

    return {
        "messages": paginated,
        "total": total,
        "unreadCount": unread_count,
        "page": page,
        "totalPages": math.ceil(total / limit) if total > 0 else 1,
    }


@router.get("/count")
def get_unread_count(db: Session = Depends(get_db)):
    query = select(ContactMessage)
    items = db.execute(query).scalars().all()
    count = sum(1 for m in items if m.status == "new" or not m.is_read)
    return {"count": count}


@router.patch("/{message_id}/read")
def mark_message_as_read(
    message_id: str,
    db: Session = Depends(get_db),
):
    m = db.get(ContactMessage, message_id)
    if m and not m.is_read:
        m.is_read = True
        db.commit()
    return {"message": "Message marked as read"}


@router.patch("/{message_id}/status", response_model=AdminContactMessageResponse)
def update_message_status(
    message_id: str,
    body: AdminMessageStatusRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    m = db.get(ContactMessage, message_id)
    if not m:
        raise HTTPException(status_code=404, detail=f"Message {message_id} not found.")

    old_status = m.status
    m.status = body.status

    db.add(AuditLog(
        user_id=current_admin.id,
        action="MESSAGE_STATUS_UPDATE",
        resource=f"message:{message_id}",
        details={"reference": m.reference, "from": old_status, "to": body.status}
    ))

    db.commit()
    db.refresh(m)
    return to_admin_message_response(m)


@router.patch("/{message_id}/priority", response_model=AdminContactMessageResponse)
def update_message_priority(
    message_id: str,
    body: AdminMessagePriorityRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    m = db.get(ContactMessage, message_id)
    if not m:
        raise HTTPException(status_code=404, detail=f"Message {message_id} not found.")

    m.priority = body.priority

    db.add(AuditLog(
        user_id=current_admin.id,
        action="MESSAGE_PRIORITY_UPDATE",
        resource=f"message:{message_id}",
        details={"reference": m.reference, "priority": body.priority}
    ))

    db.commit()
    db.refresh(m)
    return to_admin_message_response(m)


@router.patch("/{message_id}/assign", response_model=AdminContactMessageResponse)
def assign_message(
    message_id: str,
    body: AdminMessageAssignRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    m = db.get(ContactMessage, message_id)
    if not m:
        raise HTTPException(status_code=404, detail=f"Message {message_id} not found.")

    m.assignee = body.assignee

    db.add(AuditLog(
        user_id=current_admin.id,
        action="MESSAGE_ASSIGNED",
        resource=f"message:{message_id}",
        details={"reference": m.reference, "assignee": body.assignee or "Unassigned"}
    ))

    db.commit()
    db.refresh(m)
    return to_admin_message_response(m)


@router.post("/{message_id}/reply", response_model=AdminContactMessageResponse)
def add_message_reply(
    message_id: str,
    body: AdminMessageReplyRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    m = db.get(ContactMessage, message_id)
    if not m:
        raise HTTPException(status_code=404, detail=f"Message {message_id} not found.")

    current_replies = list(getattr(m, "reply_thread", []) or [])
    current_replies.append({
        "id": f"rep-{uuid.uuid4().hex[:6]}",
        "author": body.author or current_admin.username,
        "role": "Administrator",
        "message": body.message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    m.reply_thread = current_replies
    m.status = "replied"
    m.is_read = True

    db.add(AuditLog(
        user_id=current_admin.id,
        action="MESSAGE_REPLY_SENT",
        resource=f"message:{message_id}",
        details={"reference": m.reference, "author": body.author or current_admin.username}
    ))

    db.commit()
    db.refresh(m)
    return to_admin_message_response(m)


@router.post("/{message_id}/spam")
def mark_message_as_spam(
    message_id: str,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    m = db.get(ContactMessage, message_id)
    if m:
        m.status = "spam"
        m.is_read = True

        db.add(AuditLog(
            user_id=current_admin.id,
            action="MESSAGE_MARK_SPAM",
            resource=f"message:{message_id}",
            details={"reference": m.reference, "sender": m.sender_email}
        ))
        db.commit()

    return {"message": "Message marked as spam"}


@router.delete("/{message_id}")
def soft_delete_message(
    message_id: str,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    m = db.get(ContactMessage, message_id)
    if m:
        m.status = "archived"

        db.add(AuditLog(
            user_id=current_admin.id,
            action="MESSAGE_SOFT_DELETE",
            resource=f"message:{message_id}",
            details={"reference": m.reference}
        ))
        db.commit()

    return {"message": "Message archived"}
