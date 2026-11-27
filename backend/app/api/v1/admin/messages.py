import math
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.permissions import require_admin
from app.db.models.contact_message import ContactMessage
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.admin import (
    AdminContactMessageResponse,
    AdminMessageAssignRequest,
    AdminMessagePriorityRequest,
    AdminMessageReplyRequest,
    AdminMessageStatusRequest,
    AdminReplyMessage,
)
from app.services.audit import log_audit_event, utc_now

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
            timestamp=r.get("timestamp", ""),
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
    safe_page = max(1, page)
    safe_limit = max(1, min(limit, 100))

    unread_count = int(
        db.execute(
            select(func.count(ContactMessage.id)).where(
                ContactMessage.is_read.is_(False),
                ~ContactMessage.status.in_(["archived", "spam"]),
            )
        ).scalar()
        or 0
    )

    conditions = []
    if status and status != "all":
        conditions.append(func.lower(ContactMessage.status) == status.lower())
    if category and category != "all":
        conditions.append(func.lower(ContactMessage.category) == category.lower())
    if priority and priority != "all":
        conditions.append(func.lower(ContactMessage.priority) == priority.lower())
    if assignee and assignee != "all":
        if assignee == "unassigned":
            conditions.append(ContactMessage.assignee.is_(None))
        else:
            conditions.append(ContactMessage.assignee == assignee)
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        conditions.append(
            or_(
                ContactMessage.reference.ilike(pattern),
                ContactMessage.sender_name.ilike(pattern),
                ContactMessage.sender_email.ilike(pattern),
                ContactMessage.subject.ilike(pattern),
                ContactMessage.body.ilike(pattern),
            )
        )

    count_q = select(func.count(ContactMessage.id))
    list_q = select(ContactMessage)
    for cond in conditions:
        count_q = count_q.where(cond)
        list_q = list_q.where(cond)

    total = int(db.execute(count_q).scalar() or 0)
    offset = (safe_page - 1) * safe_limit
    rows = db.execute(
        list_q.order_by(ContactMessage.date.desc()).offset(offset).limit(safe_limit)
    ).scalars().all()

    return {
        "messages": [to_admin_message_response(m) for m in rows],
        "total": total,
        "unreadCount": unread_count,
        "page": safe_page,
        "totalPages": math.ceil(total / safe_limit) if total > 0 else 1,
    }


@router.get("/count")
def get_unread_count(db: Session = Depends(get_db)):
    count = int(
        db.execute(
            select(func.count(ContactMessage.id)).where(
                or_(
                    ContactMessage.status == "new",
                    (ContactMessage.is_read.is_(False)) & (~ContactMessage.status.in_(["archived", "spam"])),
                )
            )
        ).scalar()
        or 0
    )
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

    log_audit_event(
        db=db,
        user=current_admin,
        action="message.status_updated",
        resource=f"message:{message_id}",
        details={"reference": m.reference, "from": old_status, "to": body.status},
    )

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

    log_audit_event(
        db=db,
        user=current_admin,
        action="message.priority_updated",
        resource=f"message:{message_id}",
        details={"reference": m.reference, "priority": body.priority},
    )

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

    log_audit_event(
        db=db,
        user=current_admin,
        action="message.assigned",
        resource=f"message:{message_id}",
        details={"reference": m.reference, "assignee": body.assignee or "Unassigned"},
    )

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
    author_name = body.author or f"{current_admin.username} (Admin)"
    current_replies.append({
        "id": f"rep-{uuid.uuid4().hex[:6]}",
        "author": author_name,
        "role": "Administrator",
        "message": body.message,
        "timestamp": utc_now().isoformat(),
    })

    m.reply_thread = current_replies
    m.status = "replied"
    m.is_read = True

    log_audit_event(
        db=db,
        user=current_admin,
        action="message.reply_sent",
        resource=f"message:{message_id}",
        details={"reference": m.reference, "author": author_name},
    )

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

        log_audit_event(
            db=db,
            user=current_admin,
            action="message.marked_spam",
            resource=f"message:{message_id}",
            details={"reference": m.reference, "sender": m.sender_email},
        )
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

        log_audit_event(
            db=db,
            user=current_admin,
            action="message.deleted",
            resource=f"message:{message_id}",
            details={"reference": m.reference},
        )
        db.commit()

    return {"message": "Message archived"}
