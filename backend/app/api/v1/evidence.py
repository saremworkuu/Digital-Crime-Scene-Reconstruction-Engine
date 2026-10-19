import uuid
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends
from sqlalchemy.orm import Session
from typing import List, Optional
from app.db.session import get_db
from app.db.models import Evidence, Event, AuditLog
from app.schemas.evidence import EvidenceResponse, ReparseRequest
from app.services.ingestion import save_and_ingest_evidence
from app.core.security import oauth2_scheme, decode_token

router = APIRouter(prefix="/cases", tags=["evidence"])

@router.get("/{case_id}/evidence", response_model=List[EvidenceResponse])
def get_case_evidence(case_id: str, db: Session = Depends(get_db)):
    return db.query(Evidence).filter(Evidence.case_id == case_id).all()

@router.post("/{case_id}/evidence/upload", response_model=EvidenceResponse)
async def upload_evidence(
    case_id: str,
    file: UploadFile = File(...),
    parser_type: Optional[str] = Form(None),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    payload = decode_token(token)
    user_id = payload.get("sub", "usr-sarah")
    file_bytes = await file.read()
    evidence_id = f"ev-{uuid.uuid4().hex[:8]}"

    file_path, sha256_hash, parsed_events, errors = save_and_ingest_evidence(
        case_id=case_id,
        evidence_id=evidence_id,
        filename=file.filename,
        file_bytes=file_bytes,
        parser_override=parser_type
    )

    new_evidence = Evidence(
        id=evidence_id,
        case_id=case_id,
        filename=file.filename,
        file_type=parser_type or "detected",
        size_bytes=len(file_bytes),
        sha256_hash=sha256_hash,
        storage_path=file_path,
        uploader_id=user_id,
        status="Parsed" if parsed_events else ("Failed" if errors else "Pending"),
        parser_used=parser_type or "auto",
        parse_errors=errors,
        event_count=len(parsed_events)
    )
    db.add(new_evidence)

    # Ingest events to database (FR-PARSE-1..10)
    for evt in parsed_events:
        db.add(Event(**evt))

    # Audit log (FR-AUDIT-1)
    db.add(AuditLog(
        id=f"audit-{uuid.uuid4().hex[:8]}",
        user_id=user_id,
        user_name="Analyst",
        user_role=payload.get("role", "investigator"),
        case_id=case_id,
        action="EVIDENCE_UPLOADED",
        target_type="evidence",
        target_id=evidence_id,
        ip_address="127.0.0.1",
        user_agent="FastAPI",
        details_json={"filename": file.filename, "sha256": sha256_hash, "events": len(parsed_events)}
    ))

    db.commit()
    db.refresh(new_evidence)
    return new_evidence

@router.post("/evidence/{evidence_id}/reparse", response_model=EvidenceResponse)
def reparse_evidence(
    evidence_id: str,
    data: dict,
    db: Session = Depends(get_db)
):
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    parser_type = data.get("parser_type")
    
    # Placeholder for reparse logic - would need to re-run the parser
    # and update events in the database
    
    evidence.parser_used = parser_type or evidence.parser_used
    evidence.status = "Parsed"
    db.commit()
    db.refresh(evidence)
    
    return evidence

@router.delete("/evidence/{evidence_id}")
def delete_evidence(evidence_id: str, db: Session = Depends(get_db)):
    ev = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    db.delete(ev)
    db.commit()
    return {"message": "Evidence deleted"}
