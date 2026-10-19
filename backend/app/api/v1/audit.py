from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Optional
from app.db.session import get_db
from app.db.models import AuditLog
from app.schemas.report import AuditLogResponse
from app.core.security import require_role

router = APIRouter(prefix="/audit", tags=["audit"])

@router.get("", response_model=List[AuditLogResponse])
def get_audit_logs(
    case_id: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "investigator"]))  # Viewer blocked per FR-AUDIT-2
):
    query = db.query(AuditLog)
    if case_id:
        query = query.filter(AuditLog.case_id == case_id)
    return query.order_by(AuditLog.timestamp.desc()).limit(limit).all()

@router.get("/export")
def export_audit_csv(
    case_id: Optional[str] = None,
    db: Session = Depends(get_db),
    _user=Depends(require_role(["admin", "investigator"]))
):
    query = db.query(AuditLog)
    if case_id:
        query = query.filter(AuditLog.case_id == case_id)
    
    logs = query.order_by(AuditLog.timestamp.desc()).all()
    
    # Generate CSV content
    csv_lines = ["timestamp,user_id,user_name,user_role,action,target_type,target_id,ip_address"]
    for log in logs:
        csv_lines.append(
            f"{log.timestamp},{log.user_id},{log.user_name},{log.user_role},"
            f"{log.action},{log.target_type},{log.target_id},{log.ip_address}"
        )
    
    return {"csv_content": "\n".join(csv_lines), "count": len(logs)}
