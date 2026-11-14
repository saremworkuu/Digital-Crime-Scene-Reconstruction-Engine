import uuid
import time
import math
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models.contact_message import ContactMessage
from app.schemas.admin import AdminContactMessageResponse, AdminReplyMessage

router = APIRouter()


class PublicContactCreate(BaseModel):
    first_name: str = Field(..., min_length=1)
    last_name: str = Field(..., min_length=1)
    email: str = Field(..., min_length=3)
    phone: Optional[str] = ""
    message: str = Field(..., min_length=5)
    subject: Optional[str] = "Forensic Inquiry / Incident Escalation"
    category: Optional[str] = "Incident Escalation"


@router.post("", response_model=AdminContactMessageResponse, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=AdminContactMessageResponse, status_code=status.HTTP_201_CREATED)
def submit_contact_message(
    data: PublicContactCreate,
    db: Session = Depends(get_db),
):
    msg_id = f"msg-{uuid.uuid4().hex[:8]}"
    ref_ticket = f"አሻራ-{math.floor(time.time() * 1000) % 1000000:06d}"
    sender_full_name = f"{data.first_name} {data.last_name}".strip()

    is_urgent = any(k in data.message.lower() for k in ["urgent", "breach", "incident", "ransomware", "emergency"])

    new_message = ContactMessage(
        id=msg_id,
        reference=ref_ticket,
        sender_name=sender_full_name,
        sender_email=data.email.strip(),
        sender_phone=data.phone.strip() if data.phone else "",
        subject=data.subject or "Forensic Incident Inquiry",
        category=data.category or "Incident Escalation",
        status="new",
        priority="high" if is_urgent else "medium",
        assignee=None,
        date=datetime.now(timezone.utc),
        is_read=False,
        body=data.message.strip(),
        reply_thread=[],
    )

    db.add(new_message)
    db.commit()
    db.refresh(new_message)

    date_str = new_message.date.isoformat() if hasattr(new_message.date, "isoformat") else str(new_message.date)

    return AdminContactMessageResponse(
        id=new_message.id,
        reference=new_message.reference,
        sender_name=new_message.sender_name,
        sender_email=new_message.sender_email,
        sender_phone=new_message.sender_phone,
        subject=new_message.subject,
        category=new_message.category,
        status=new_message.status,
        priority=new_message.priority,
        assignee=new_message.assignee,
        date=date_str,
        is_read=new_message.is_read,
        body=new_message.body,
        reply_thread=[],
    )
