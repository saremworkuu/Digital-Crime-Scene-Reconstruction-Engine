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

    from app.services.event_ordering import sort_events

    events = sort_events(
        db.execute(
            select(Event)
            .where(Event.case_id == case.id)
            .order_by(Event.timestamp.asc(), Event.id.asc())
        ).scalars().all()
    )

    detections = db.execute(select(Detection).where(Detection.case_id == case.id)).scalars().all()
    if not detections and events:
        from app.api.v1.detections import _execute_case_detections
        detections = _execute_case_detections(case.id, db)
    findings = []
    for detection in detections:
        info = detection.rule_information or {}
        findings.append({
            "rule_id": detection.rule_id,
            "rule_name": detection.rule_name,
            "mitre_tactic": info.get("tactic") or "",
            "mitre_technique": detection.mitre_technique,
            "description": detection.description,
            "actor": info.get("actor"),
            "actor_role": info.get("actor_role"),
            "target_host": info.get("target_host") or info.get("host"),
            "target_role": info.get("target_role"),
            "hosts": info.get("hosts") or [],
            "source_ips": info.get("source_ips") or info.get("src_ips") or ([info["src_ip"]] if info.get("src_ip") else []),
            "src_ip": info.get("src_ip"),
            "dst_ip": info.get("dst_ip") or info.get("destination_ip"),
            "user": info.get("user"),
            "users": info.get("users") or [],
            "matching_event_ids": info.get("matching_event_ids") or [],
            "rule_information": info,
        })
    return build_attack_graph(events, attack_path_only=attack_path_only, findings=findings)
