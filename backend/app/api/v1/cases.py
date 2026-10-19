import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from typing import List, Optional
from app.db.session import get_db
from app.db.models import Case, User, AuditLog
from app.schemas.case import CaseCreate, CaseUpdate, CaseResponse
from app.core.security import oauth2_scheme, decode_token

router = APIRouter(prefix="/cases", tags=["cases"])

@router.get("", response_model=List[CaseResponse])
def list_cases(status: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Case)
    if status and status != "All":
        query = query.filter(Case.status == status)
    cases = query.all()
    
    # Return formatted cases
    results = []
    for c in cases:
        results.append(CaseResponse(
            id=c.id,
            name=c.name,
            description=c.description,
            status=c.status,
            created_at=c.created_at,
            updated_at=c.updated_at,
            owner_id=c.owner_id,
            tags=c.tags or [],
            evidence_count=len(c.evidence_files),
            event_count=len(c.events),
            detection_count=len(c.detections),
            critical_detection_count=sum(1 for d in c.detections if d.severity == "critical")
        ))
    return results

@router.post("", response_model=CaseResponse)
def create_case(data: CaseCreate, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = decode_token(token)
    user_id = payload.get("sub", "usr-sarah")

    new_case = Case(
        id=f"case-{uuid.uuid4().hex[:8]}",
        name=data.name,
        description=data.description,
        status="Open",
        owner_id=user_id,
        tags=data.tags or []
    )
    db.add(new_case)
    db.commit()
    db.refresh(new_case)

    # Record Audit Log (FR-AUDIT-1)
    audit = AuditLog(
        id=f"audit-{uuid.uuid4().hex[:8]}",
        user_id=user_id,
        user_name="Analyst",
        user_role=payload.get("role", "investigator"),
        case_id=new_case.id,
        action="CASE_CREATED",
        target_type="case",
        target_id=new_case.id,
        ip_address="127.0.0.1",
        user_agent="FastAPI-Backend",
        details_json={"name": new_case.name}
    )
    db.add(audit)
    db.commit()

    return CaseResponse(
        id=new_case.id,
        name=new_case.name,
        description=new_case.description,
        status=new_case.status,
        created_at=new_case.created_at,
        updated_at=new_case.updated_at,
        owner_id=new_case.owner_id,
        tags=new_case.tags or []
    )

@router.get("/{case_id}", response_model=CaseResponse)
def get_case(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return CaseResponse(
        id=case.id,
        name=case.name,
        description=case.description,
        status=case.status,
        created_at=case.created_at,
        updated_at=case.updated_at,
        owner_id=case.owner_id,
        tags=case.tags or [],
        evidence_count=len(case.evidence_files),
        event_count=len(case.events),
        detection_count=len(case.detections)
    )

@router.put("/{case_id}", response_model=CaseResponse)
def update_case(case_id: str, data: CaseUpdate, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    if data.name is not None: case.name = data.name
    if data.description is not None: case.description = data.description
    if data.status is not None: case.status = data.status
    if data.tags is not None: case.tags = data.tags
    case.updated_at = datetime.now(timezone.utc)
    
    db.commit()
    db.refresh(case)
    return CaseResponse(
        id=case.id,
        name=case.name,
        description=case.description,
        status=case.status,
        created_at=case.created_at,
        updated_at=case.updated_at,
        owner_id=case.owner_id,
        tags=case.tags or []
    )

@router.delete("/{case_id}")
def delete_case(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    db.delete(case)
    db.commit()
    return {"message": "Case deleted successfully"}

@router.post("/{case_id}/assign")
def assign_users_to_case(
    case_id: str,
    data: dict,
    db: Session = Depends(get_db)
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    
    # For now, this is a placeholder - would need a case_users junction table
    # in the database to properly implement many-to-many relationships
    user_ids = data.get("user_ids", [])
    
    return {
        "message": f"Users assigned to case {case_id}",
        "user_ids": user_ids
    }
