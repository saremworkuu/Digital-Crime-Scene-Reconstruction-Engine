import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.session import get_db
from app.db.models.events import Event
from app.db.models.user import User
from app.schemas.graph import AttackGraphData
from app.services.graph import build_attack_graph
from app.core.permissions import get_authorized_case

router = APIRouter(tags=["graph"])


@router.get("/{case_id}/graph", response_model=AttackGraphData)
@router.get("/cases/{case_id}/graph", response_model=AttackGraphData)
def get_attack_graph(
    case_id: str,
    attack_path_only: bool = Query(default=False),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    case = get_authorized_case(
        case_id=case_id,
        current_user=current_user,
        db=db,
        allow_viewer=True,
    )

    events = db.execute(
        select(Event)
        .where(Event.case_id == case.id)
        .order_by(Event.timestamp.asc(), Event.id.asc())
    ).scalars().all()

    return build_attack_graph(events, attack_path_only=attack_path_only)
