from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from app.db.session import get_db
from app.db.models import Event
from app.schemas.event import EventResponse

router = APIRouter(prefix="/cases", tags=["timeline"])

@router.get("/{case_id}/timeline", response_model=List[EventResponse])
def get_timeline(
    case_id: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: Optional[int] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Event).filter(Event.case_id == case_id)
    
    if start_time:
        try:
            start_dt = datetime.fromisoformat(start_time)
            query = query.filter(Event.timestamp >= start_dt)
        except ValueError:
            pass
    
    if end_time:
        try:
            end_dt = datetime.fromisoformat(end_time)
            query = query.filter(Event.timestamp <= end_dt)
        except ValueError:
            pass
    
    query = query.order_by(Event.timestamp.asc())
    
    if limit:
        query = query.limit(limit)
    
    return query.all()
