import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.models.case import Case
from app.db.models.detection import Detection, DetectionSeverity
from app.db.models.detection_event import DetectionEvent
from app.db.models.events import Event
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.detection import DetectionResponse, FalsePositiveRequest, DetectionRuleResponse
from app.services.detection import (
    detect_repeated_failed_logins,
    detect_failed_then_successful_login,
    detect_privilege_escalation,
    detect_lateral_movement,
    detect_web_sql_injection,
    detect_data_exfiltration,
    detect_dns_tunneling,
)
from app.services.rule_loader import load_all_rules
from app.services.audit import log_audit_event
from app.core.permissions import get_authorized_case

router = APIRouter()


def build_detection_response(db: Session, detection: Detection) -> DetectionResponse:
    event_ids = db.execute(
        select(DetectionEvent.event_id).where(
            DetectionEvent.detection_id == detection.id
        )
    ).scalars().all()

    rule_info = detection.rule_information or {}
    ts_str = (
        detection.detected_at.isoformat()
        if hasattr(detection.detected_at, "isoformat")
        else str(detection.detected_at or "")
    )

    return DetectionResponse(
        id=detection.id,
        case_id=detection.case_id,
        rule_id=detection.rule_id,
        rule_name=detection.rule_name,
        severity=detection.severity,
        description=detection.description,
        mitre_technique=detection.mitre_technique or "T1110",
        mitre_tactic=rule_info.get("tactic", "Execution"),
        rule_information=rule_info,
        is_false_positive=detection.is_false_positive,
        false_positive=detection.is_false_positive,
        false_positive_reason=rule_info.get("fp_reason"),
        detected_at=detection.detected_at,
        timestamp=ts_str,
        event_ids=event_ids,
        matched_event_ids=[str(eid) for eid in event_ids],
        entities_involved=rule_info.get("entities", {"hosts": [], "users": [], "ips": []}),
    )


def _execute_case_detections(case_id: uuid.UUID, db: Session) -> List[Detection]:
    events = db.execute(
        select(Event)
        .where(Event.case_id == case_id)
        .order_by(Event.timestamp.asc(), Event.id.asc())
    ).scalars().all()

    findings = []
    try:
        findings.extend(detect_repeated_failed_logins(events))
    except Exception:
        pass
    try:
        findings.extend(detect_failed_then_successful_login(events))
    except Exception:
        pass
    try:
        findings.extend(detect_privilege_escalation(events))
    except Exception:
        pass
    try:
        findings.extend(detect_lateral_movement(events))
    except Exception:
        pass
    try:
        findings.extend(detect_web_sql_injection(events))
    except Exception:
        pass
    try:
        findings.extend(detect_data_exfiltration(events))
    except Exception:
        pass
    try:
        findings.extend(detect_dns_tunneling(events))
    except Exception:
        pass

    saved_detections = []
    for finding in findings:
        rule_id = finding.get("rule_id", finding.get("rule_name", "detection-rule"))
        description = finding["description"]

        detection = db.execute(
            select(Detection).where(
                Detection.case_id == case_id,
                Detection.rule_id == rule_id,
                Detection.description == description,
            )
        ).scalar_one_or_none()

        matching_ids = {
            uuid.UUID(str(event_id))
            for event_id in finding.get("matching_event_ids", [])
        }

        sev_val = finding.get("severity", "medium").lower()
        try:
            sev_enum = DetectionSeverity(sev_val)
        except ValueError:
            sev_enum = DetectionSeverity.MEDIUM

        if detection is None:
            detection = Detection(
                case_id=case_id,
                rule_id=rule_id,
                rule_name=finding.get("display_name", finding.get("rule_name", "Security Alert")),
                severity=sev_enum,
                description=description,
                mitre_technique=finding.get("mitre_technique", "T1059"),
                rule_information=finding.get("rule_information", {}),
                is_false_positive=False,
            )
            db.add(detection)
            db.flush()
        else:
            detection.severity = sev_enum
            detection.mitre_technique = finding.get("mitre_technique", detection.mitre_technique)

        if matching_ids:
            existing_ids = set(
                db.execute(
                    select(DetectionEvent.event_id).where(
                        DetectionEvent.detection_id == detection.id,
                        DetectionEvent.event_id.in_(matching_ids),
                    )
                ).scalars().all()
            )
            for event_id in matching_ids - existing_ids:
                db.add(DetectionEvent(detection_id=detection.id, event_id=event_id))

        saved_detections.append(detection)

    db.commit()
    for d in saved_detections:
        db.refresh(d)
    return saved_detections


@router.post(
    "/cases/{case_id}/run",
    response_model=List[DetectionResponse],
)
def run_detection(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    case = get_authorized_case(case_id=case_id, current_user=current_user, db=db, allow_viewer=False)
    detections = _execute_case_detections(case.id, db)
    return [build_detection_response(db, d) for d in detections]


@router.get(
    "/cases/{case_id}/detections",
    response_model=List[DetectionResponse],
)
def get_case_detections(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    case = get_authorized_case(case_id=case_id, current_user=current_user, db=db, allow_viewer=True)

    detections = db.execute(
        select(Detection)
        .where(Detection.case_id == case.id)
        .order_by(Detection.detected_at.desc())
    ).scalars().all()

    if not detections:
        # Run detectors automatically so findings appear immediately
        detections = _execute_case_detections(case.id, db)

    return [build_detection_response(db, d) for d in detections]


@router.post("/{detection_id}/false-positive")
@router.post("/detections/{detection_id}/false-positive")
def toggle_false_positive(
    detection_id: uuid.UUID,
    payload: FalsePositiveRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    detection = db.get(Detection, detection_id)
    if detection is None:
        raise HTTPException(status_code=404, detail="Detection not found.")

    get_authorized_case(case_id=detection.case_id, current_user=current_user, db=db, allow_viewer=False)

    detection.is_false_positive = payload.false_positive
    info = detection.rule_information or {}
    if payload.reason:
        info["fp_reason"] = payload.reason
    info["fp_marked_by"] = current_user.username
    detection.rule_information = info

    log_audit_event(
        db=db,
        user=current_user,
        action="detection.false_positive_toggled",
        resource=f"detection:{detection.id}",
        request=request,
        case_id=detection.case_id,
        details={
            "rule_name": detection.rule_name,
            "false_positive": payload.false_positive,
            "reason": payload.reason,
        },
    )

    db.commit()
    db.refresh(detection)
    return build_detection_response(db, detection)


@router.get("/rules", response_model=List[DetectionRuleResponse])
@router.get("/detections/rules", response_model=List[DetectionRuleResponse])
def get_detection_rules(
    current_user: User = Depends(get_current_user),
):
    raw_rules = load_all_rules()
    return [
        DetectionRuleResponse(
            id=r.get("id", "rule"),
            name=r.get("title", r.get("id")),
            severity=r.get("severity", "medium"),
            mitre_technique=r.get("mitre_technique", "T1059"),
            mitre_tactic=r.get("mitre_tactic", "Execution"),
            description=r.get("description", ""),
            author=r.get("author", "DCSRE Forensics Team"),
            status=r.get("status", "active"),
            tags=r.get("tags", []),
            yaml_content=r.get("yaml_content"),
        )
        for r in raw_rules
    ]


@router.post("/rules/reload")
@router.post("/detections/rules/reload")
def reload_detection_rules(
    current_user: User = Depends(get_current_user),
):
    rules = load_all_rules()
    return {"message": f"Successfully reloaded {len(rules)} detection rules from disk."}


@router.get(
    "/",
    response_model=List[DetectionResponse],
)
def get_detections(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = select(Detection).join(Case, Detection.case_id == Case.id).where(Case.is_deleted.is_(False))
    if current_user.role != "admin":
        query = query.where(Case.created_by == current_user.id)

    detections = db.execute(query.order_by(Detection.detected_at.desc())).scalars().all()
    return [build_detection_response(db, detection) for detection in detections]


@router.get(
    "/{detection_id}",
    response_model=DetectionResponse,
)
def get_detection(
    detection_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    detection = db.get(Detection, detection_id)
    if detection is None:
        raise HTTPException(status_code=404, detail="Detection not found.")

    get_authorized_case(case_id=detection.case_id, current_user=current_user, db=db, allow_viewer=True)
    return build_detection_response(db, detection)
