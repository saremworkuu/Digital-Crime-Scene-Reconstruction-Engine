import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.session import get_db
from app.db.models.events import Event
from app.db.models.detection import Detection
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

    from app.api.v1.detections import _execute_case_detections
    _execute_case_detections(case.id, db)
    detections = db.execute(select(Detection).where(Detection.case_id == case.id)).scalars().all()
    findings = []
    for detection in detections:
        info = detection.rule_information or {}
        findings.append({
            "actor": info.get("actor"), "actor_role": info.get("actor_role"),
            "target_host": info.get("target_host") or info.get("host"),
            "target_role": info.get("target_role"),
        })
    return build_attack_graph(events, attack_path_only=attack_path_only, findings=findings)
