import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.models.events import Event
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.events import EventResponse
from sqlalchemy import select, func

from app.core.permissions import get_authorized_case

router = APIRouter()


@router.get("/", response_model=list[EventResponse])
def get_events(
    case_id: uuid.UUID,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
   
    # Find the case and verify the user's access.
    get_authorized_case(
        case_id=case_id,
        current_user=current_user,
        db=db,
        allow_viewer=True,
    )

    # 3. Retrieve events in chronological order.
    events = db.execute(
        select(Event)
        .where(Event.case_id == case_id)
        .order_by(Event.timestamp.asc(), Event.id.asc())
        .limit(limit)
        .offset(offset)
    ).scalars().all()

    return events
