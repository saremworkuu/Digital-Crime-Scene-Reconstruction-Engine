from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import Case, Evidence, Event, Detection
from app.schemas.report import ForensicReportResponse
from app.services.report import generate_forensic_report_data

router = APIRouter(prefix="/cases", tags=["reports"])

@router.post("/{case_id}/reports/generate", response_model=ForensicReportResponse)
def generate_report(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    evidence = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    events = db.query(Event).filter(Event.case_id == case_id).all()
    detections = db.query(Detection).filter(Detection.case_id == case_id).all()

    report_data = generate_forensic_report_data(
        case_dict={"id": case.id, "name": case.name},
        evidence_list=[{"filename": e.filename, "sha256_hash": e.sha256_hash, "size_bytes": e.size_bytes, "event_count": e.event_count, "uploaded_at": e.uploaded_at} for e in evidence],
        events=[{"action": ev.action, "host": ev.host, "user": ev.user, "src_ip": ev.src_ip, "timestamp": ev.timestamp, "severity": ev.severity, "is_attack_path": ev.is_attack_path, "attack_phase": ev.attack_phase} for ev in events],
        detections=[{"mitre_tactic": d.mitre_tactic, "mitre_technique": d.mitre_technique, "rule_name": d.rule_name, "severity": d.severity} for d in detections]
    )
    return report_data

@router.get("/{case_id}/reports/pdf")
def export_pdf(case_id: str, db: Session = Depends(get_db)):
    # Placeholder for PDF generation
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    return {"message": "PDF export not yet implemented", "case_id": case_id}

@router.get("/{case_id}/reports/html")
def export_html(case_id: str, db: Session = Depends(get_db)):
    # Placeholder for HTML export
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    return {"message": "HTML export not yet implemented", "case_id": case_id}
