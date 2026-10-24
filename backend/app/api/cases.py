import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import Case, CaseNote, TimelineEvent, User
from app.schemas.schemas import (
    CaseCreate,
    CaseNoteCreate,
    CaseNoteOut,
    CaseOut,
    CaseUpdate,
    TimelineEventCreate,
    TimelineEventOut,
)
from app.services.response import audit
from app.services.seed import ensure_default_user

router = APIRouter(prefix="/cases", tags=["cases"])


def _resolve_creator(db: Session, created_by: uuid.UUID | None) -> User:
    if created_by is not None:
        user = db.get(User, created_by)
        if not user:
            raise HTTPException(400, "created_by user not found")
        return user
    return ensure_default_user(db)


@router.get("", response_model=list[CaseOut])
def list_cases(db: Session = Depends(get_db)):
    return db.query(Case).order_by(Case.created_at.desc()).all()


@router.get("/next-id")
def suggest_next_case_id(db: Session = Depends(get_db)):
    """Suggest the next INC-YYYY-NNNN case id for the current year."""
    year = datetime.now(timezone.utc).year
    prefix = f"INC-{year}-"
    existing = (
        db.query(Case.case_id)
        .filter(Case.case_id.like(f"{prefix}%"))
        .order_by(Case.case_id.desc())
        .all()
    )
    next_num = 1
    if existing:
        try:
            next_num = int(existing[0][0].rsplit("-", 1)[-1]) + 1
        except ValueError:
            next_num = 1
    return {"case_id": f"{prefix}{next_num:04d}"}


@router.post("", response_model=CaseOut, status_code=201)
def create_case(payload: CaseCreate, db: Session = Depends(get_db)):
    if db.query(Case).filter(Case.case_id == payload.case_id).first():
        raise HTTPException(409, f"Case ID {payload.case_id} already exists")
    creator = _resolve_creator(db, payload.created_by)
    data = payload.model_dump()
    data["created_by"] = creator.id
    case = Case(**data)
    db.add(case)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, f"Case ID {payload.case_id} already exists")
    audit(
        db,
        case.id,
        "case_created",
        f"Created {case.case_id}: '{case.title}'",
        actor=creator.username,
    )
    _seed_demo_timeline(db, case)
    db.commit()
    db.refresh(case)
    return case


@router.get("/{case_id}", response_model=CaseOut)
def get_case(case_id: uuid.UUID, db: Session = Depends(get_db)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    return case


@router.patch("/{case_id}", response_model=CaseOut)
def update_case(case_id: uuid.UUID, payload: CaseUpdate, db: Session = Depends(get_db)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    data = payload.model_dump(exclude_unset=True)
    if "case_id" in data and data["case_id"] != case.case_id:
        clash = db.query(Case).filter(Case.case_id == data["case_id"]).first()
        if clash:
            raise HTTPException(409, f"Case ID {data['case_id']} already exists")
    for key, value in data.items():
        setattr(case, key, value)
    if "status" in data:
        audit(db, case.id, "status_change", f"Status → {data['status']}")
    db.commit()
    db.refresh(case)
    return case


@router.delete("/{case_id}", status_code=204)
def delete_case(case_id: uuid.UUID, db: Session = Depends(get_db)):
    """Permanently delete a finished (closed) investigation. Open cases are blocked."""
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    if case.status != "closed":
        raise HTTPException(
            400,
            "Only closed investigations can be deleted. Set status to closed first.",
        )
    db.delete(case)
    db.commit()
    return None


@router.get("/{case_id}/notes", response_model=list[CaseNoteOut])
def list_notes(case_id: uuid.UUID, db: Session = Depends(get_db)):
    if not db.get(Case, case_id):
        raise HTTPException(404, "Case not found")
    return (
        db.query(CaseNote)
        .filter(CaseNote.case_id == case_id)
        .order_by(CaseNote.created_at.desc())
        .all()
    )


@router.post("/{case_id}/notes", response_model=CaseNoteOut, status_code=201)
def add_note(case_id: uuid.UUID, payload: CaseNoteCreate, db: Session = Depends(get_db)):
    if not db.get(Case, case_id):
        raise HTTPException(404, "Case not found")
    note = CaseNote(case_id=case_id, **payload.model_dump())
    db.add(note)
    audit(db, case_id, "note_added", payload.body[:120], actor=payload.author)
    db.commit()
    db.refresh(note)
    return note


@router.get("/{case_id}/timeline", response_model=list[TimelineEventOut])
def list_timeline(case_id: uuid.UUID, db: Session = Depends(get_db)):
    if not db.get(Case, case_id):
        raise HTTPException(404, "Case not found")
    return (
        db.query(TimelineEvent)
        .filter(TimelineEvent.case_id == case_id)
        .order_by(TimelineEvent.timestamp.asc())
        .all()
    )


@router.post("/{case_id}/timeline", response_model=TimelineEventOut, status_code=201)
def add_timeline_event(
    case_id: uuid.UUID, payload: TimelineEventCreate, db: Session = Depends(get_db)
):
    if not db.get(Case, case_id):
        raise HTTPException(404, "Case not found")
    event = TimelineEvent(case_id=case_id, **payload.model_dump())
    db.add(event)
    audit(db, case_id, "timeline_event", payload.summary[:120])
    db.commit()
    db.refresh(event)
    return event


def _seed_demo_timeline(db: Session, case: Case) -> None:
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    samples = [
        (-6, "mail_gateway", "mail-01", "jdoe", "Phishing email delivered with credential lure", "medium", True),
        (-5, "auth", "idp", "jdoe", "Successful login from unusual geo after link click", "high", True),
        (-4, "edr", "ws-1042", "jdoe", "PowerShell spawned from Office process", "high", True),
        (-3, "proxy", "ws-1042", "jdoe", "Outbound connection to suspicious domain", "high", True),
        (-2, "auth", "dc-01", "svc_backup", "Service account used for lateral movement attempt", "critical", True),
        (-1, "siem", "siem", "system", "Correlation rule fired: account compromise pattern", "high", True),
    ]
    for hours, source, host, user, summary, severity, suspicious in samples:
        db.add(
            TimelineEvent(
                case_id=case.id,
                timestamp=now + timedelta(hours=hours),
                source=source,
                host=host,
                user=user,
                summary=summary,
                severity=severity,
                is_suspicious=suspicious,
            )
        )
