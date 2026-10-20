import uuid
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, or_
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.models.events import Event
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.events import EventResponse
from app.core.permissions import get_authorized_case

router = APIRouter()


def _get_events_core(
    case_id: uuid.UUID | str,
    host: Optional[str],
    user: Optional[str],
    severity: Optional[str],
    limit: int,
    offset: int,
    current_user: User,
    db: Session,
) -> List[Event]:
    case = get_authorized_case(
        case_id=case_id,
        current_user=current_user,
        db=db,
        allow_viewer=True,
    )

    query = select(Event).where(Event.case_id == case.id)

    if host:
        pattern = f"%{host}%"
        query = query.where(
            or_(
                Event.source.ilike(pattern),
                Event.details["host"].astext.ilike(pattern),
                Event.details["Computer"].astext.ilike(pattern),
            )
        )

    if user:
        pattern = f"%{user}%"
        query = query.where(
            or_(
                Event.details["user"].astext.ilike(pattern),
                Event.details["username"].astext.ilike(pattern),
                Event.details["TargetUserName"].astext.ilike(pattern),
            )
        )

    if severity:
        pattern = f"%{severity}%"
        query = query.where(
            Event.details["severity"].astext.ilike(pattern)
        )

    events = db.execute(
        query.order_by(Event.timestamp.asc(), Event.id.asc())
        .limit(limit)
        .offset(offset)
    ).scalars().all()

    return events


# Query-param based events lookup (?case_id=...)
@router.get("/", response_model=List[EventResponse])
def get_events_by_query(
    case_id: str = Query(...),
    host: Optional[str] = Query(None),
    user: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _get_events_core(case_id, host, user, severity, limit, offset, current_user, db)


# Path-param based case events lookup (/cases/{case_id}/events)
@router.get("/cases/{case_id}/events", response_model=List[EventResponse])
def get_case_events(
    case_id: str,
    host: Optional[str] = Query(None),
    user: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return _get_events_core(case_id, host, user, severity, limit, offset, current_user, db)


@router.get("/{event_id}", response_model=EventResponse)
def get_event_detail(
    event_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found.")

    get_authorized_case(
        case_id=event.case_id,
        current_user=current_user,
        db=db,
        allow_viewer=True,
    )

    return event
