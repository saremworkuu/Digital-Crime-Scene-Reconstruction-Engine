import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.models.case import Case
from app.db.models.detection import Detection, DetectionSeverity
from app.db.models.detection_event import DetectionEvent
from app.db.models.events import Event
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.detection import DetectionResponse
from app.services.detection import (
    detect_repeated_failed_logins,
    detect_failed_then_successful_login,
    detect_privilege_escalation,
    detect_lateral_movement,
    detect_web_sql_injection,
    detect_data_exfiltration,
    detect_dns_tunneling
)

router = APIRouter()

def build_detection_response(db: Session, detection: Detection):
    event_ids = db.execute(
        select(DetectionEvent.event_id).where(
            DetectionEvent.detection_id == detection.id
        )
    ).scalars().all()

    return DetectionResponse(
        **{
            field: getattr(detection, field)
            for field in DetectionResponse.model_fields
            if field != "event_ids"
        },
        event_ids=event_ids,
    )



@router.post(
    "/cases/{case_id}/run",
    response_model=list[DetectionResponse],
)
def run_detection(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Confirm that this case exists and belongs to the current user.
    case_query = select(Case).where(
        Case.id == case_id,
        Case.is_deleted.is_(False),
    )

# Investigators can access only their own cases.
# Admins can access cases created by any investigator.
    if current_user.role != "admin":
        case_query = case_query.where(
            Case.created_by == current_user.id
    )

    case = db.execute(case_query).scalar_one_or_none()

    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found.",
        )

    # Load only events belonging to this case.
    events = db.execute(
        select(Event)
        .where(Event.case_id == case_id)
        .order_by(Event.timestamp.asc(), Event.id.asc())
    ).scalars().all()

    # Run the existing 30-minute failed-login detector.
    findings = detect_repeated_failed_logins(events)

    findings.extend(
        detect_failed_then_successful_login(events)
    )

    findings.extend(
        detect_privilege_escalation(events)
    )

    findings.extend(
        detect_lateral_movement(events)
    )

    findings.extend(
        detect_web_sql_injection(events)
    )

    findings.extend(
        detect_data_exfiltration(events)
    )

    findings.extend(
        detect_dns_tunneling(events)
    )

    saved_detections = []

    for finding in findings:
        rule_id = finding.get("rule_id", finding["rule_name"])
        description = finding["description"]

        # Reuse an identical finding instead of creating a duplicate.
        detection = db.execute(
            select(Detection).where(
                Detection.case_id == case_id,
                Detection.rule_id == rule_id,
                Detection.description == description,
            )
        ).scalar_one_or_none()
        

        # Link the detection to the events that triggered it.
        matching_ids = {
            uuid.UUID(event_id)
            for event_id in finding["matching_event_ids"]
        }
        
        if detection is None:
            detection = Detection(
                case_id=case_id,
                rule_id=rule_id,
                rule_name=finding.get(
                    "display_name",
                    "Repeated Failed Logins",
                ),
                severity=DetectionSeverity(finding["severity"]),
                description=description,
                mitre_technique=finding.get("mitre_technique", "T1110"),
                rule_information=finding.get(
                    "rule_information",
                    {
                        "threshold": 5,
                        "window_minutes": 30,
                        "grouped_by": "source_ip",
                    },
                ),
                is_false_positive=False,
            )
            db.add(detection)
            db.flush()
        else:
            # Update metadata on an existing matching detection.
            detection.rule_name = finding.get(
                "display_name",
                "Repeated Failed Logins",
            )
            detection.severity = DetectionSeverity(finding["severity"])
            detection.mitre_technique = finding.get("mitre_technique", "T1110")
            detection.rule_information = finding.get(
                "rule_information",
                detection.rule_information,
            )


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
                db.add(
                    DetectionEvent(
                        detection_id=detection.id,
                        event_id=event_id,
                    )
                )

        saved_detections.append(detection)

    db.commit()

    for detection in saved_detections:
        db.refresh(detection)

    return [
        build_detection_response(db, detection)
        for detection in saved_detections
    ]


@router.get(
    "/",
    response_model=list[DetectionResponse],
)
def get_detections(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    detections = db.execute(
        select(Detection)
        .join(Case, Detection.case_id == Case.id)
        .where(
            Case.created_by == current_user.id,
            Case.is_deleted.is_(False),
        )
        .order_by(Detection.detected_at.desc())
    ).scalars().all()

    return [
        build_detection_response(db, detection)
        for detection in detections
    ]


@router.get(
    "/{detection_id}",
    response_model=DetectionResponse,
)
def get_detection(
    detection_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    detection = db.execute(
        select(Detection)
        .join(Case, Detection.case_id == Case.id)
        .where(
            Detection.id == detection_id,
            Case.created_by == current_user.id,
            Case.is_deleted.is_(False),
        )
    ).scalar_one_or_none()

    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found.",
        )

    return build_detection_response(db, detection)
