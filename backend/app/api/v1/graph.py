from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import Event
from app.services.graph import build_attack_graph

router = APIRouter(prefix="/cases", tags=["graph"])

@router.get("/{case_id}/graph")
def get_attack_graph(case_id: str, attack_path_only: bool = False, db: Session = Depends(get_db)):
    events = db.query(Event).filter(Event.case_id == case_id).all()
    event_dicts = [
        {
            "id": e.id,
            "host": e.host,
            "user": e.user,
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "action": e.action,
            "severity": e.severity,
            "is_attack_path": e.is_attack_path
        }
        for e in events
    ]
    return build_attack_graph(event_dicts, attack_path_only=attack_path_only)
