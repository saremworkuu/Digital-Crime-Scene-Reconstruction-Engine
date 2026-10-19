from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from typing import List
from app.db.session import get_db
from app.db.models import Detection, Event, AuditLog
from app.schemas.detection import DetectionResponse, FalsePositiveToggleRequest
from app.services.detection import evaluate_events_against_rules, load_yaml_rules

router = APIRouter(prefix="/cases", tags=["detections"])

@router.get("/{case_id}/detections", response_model=List[DetectionResponse])
def get_detections(case_id: str, db: Session = Depends(get_db)):
    existing = db.query(Detection).filter(Detection.case_id == case_id).all()
    if not existing:
        # Evaluate on the fly
        events = db.query(Event).filter(Event.case_id == case_id).all()
        event_dicts = [
            {
                "id": e.id,
                "timestamp": e.timestamp,
                "host": e.host,
                "user": e.user,
                "src_ip": e.src_ip,
                "dst_ip": e.dst_ip,
                "action": e.action,
                "severity": e.severity,
                "mitre_technique": e.mitre_technique
            }
            for e in events
        ]
        rules = load_yaml_rules()
        detections = evaluate_events_against_rules(event_dicts, rules)
        for det in detections:
            db_det = Detection(
                id=f"det-{det['id']}",
                case_id=case_id,
                rule_id=det['rule_id'],
                rule_name=det['rule_name'],
                severity=det['severity'],
                mitre_technique=det['mitre_technique'],
                mitre_tactic=det['mitre_tactic'],
                timestamp=det['timestamp'],
                description=det['description'],
                matched_event_ids=det['matched_event_ids']
            )
            db.add(db_det)
        db.commit()
        existing = db.query(Detection).filter(Detection.case_id == case_id).all()
    return existing

@router.post("/detections/{detection_id}/false-positive")
def toggle_false_positive(
    detection_id: str,
    data: dict,
    db: Session = Depends(get_db)
):
    detection = db.query(Detection).filter(Detection.id == detection_id).first()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")
    
    detection.false_positive = data.get("false_positive", False)
    detection.false_positive_reason = data.get("reason")
    detection.false_positive_marked_by = "current_user"  # Would get from token
    db.commit()
    
    return {"message": "False positive status updated"}

@router.get("/detections/rules")
def list_rules():
    from app.services.detection import load_yaml_rules
    rules = load_yaml_rules()
    return [
        {
            "id": rule.get("id"),
            "name": rule.get("name"),
            "severity": rule.get("severity"),
            "mitre_technique": rule.get("mitre_technique"),
            "mitre_tactic": rule.get("mitre_tactic"),
            "description": rule.get("description")
        }
        for rule in rules
    ]

@router.post("/detections/rules/reload")
def reload_rules():
    from app.services.detection import load_yaml_rules
    rules = load_yaml_rules()
    return {"message": "Rules reloaded successfully", "count": len(rules)}
