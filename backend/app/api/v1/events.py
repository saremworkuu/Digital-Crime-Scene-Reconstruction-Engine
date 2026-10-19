from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from app.db.session import get_db
from app.db.models import Event
from app.schemas.event import EventResponse

router = APIRouter(prefix="/cases", tags=["events"])

@router.get("/{case_id}/events", response_model=List[EventResponse])
def get_case_events(
    case_id: str,
    host: Optional[str] = None,
    user: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Event).filter(Event.case_id == case_id)
    if host:
        query = query.filter(Event.host == host)
    if user:
        query = query.filter(Event.user == user)
    if severity and severity != "all":
        query = query.filter(Event.severity == severity)
    return query.order_by(Event.timestamp.asc()).all()

@router.get("/events/{event_id}", response_model=EventResponse)
def get_event_by_id(event_id: str, db: Session = Depends(get_db)):
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
