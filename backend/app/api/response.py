import uuid

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import Case, IOC, Playbook, ResponseTask, TechniqueHit, AuditLog
from app.schemas.schemas import (
    ApplyPlaybookRequest,
    AuditLogOut,
    IOCCreate,
    IOCOut,
    IOCUpdate,
    PlaybookOut,
    ResponseSummary,
    TaskCreate,
    TaskOut,
    TaskUpdate,
    TechniqueCreate,
    TechniqueOut,
)
from app.services.mitre import resolve_technique
from app.services.response import (
    apply_playbook,
    audit,
    build_response_summary,
    default_ioc_response,
    ir_handoff_markdown,
    mark_task_status,
)

router = APIRouter(tags=["incident-response"])


@router.get("/playbooks", response_model=list[PlaybookOut])
def list_playbooks(db: Session = Depends(get_db)):
    return db.query(Playbook).order_by(Playbook.name.asc()).all()


@router.post("/cases/{case_id}/apply-playbook", response_model=list[TaskOut])
def apply_case_playbook(
    case_id: uuid.UUID, payload: ApplyPlaybookRequest, db: Session = Depends(get_db)
):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    playbook = db.get(Playbook, payload.playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    tasks = apply_playbook(db, case, playbook, owner=payload.owner)
    db.commit()
    for t in tasks:
        db.refresh(t)
    return tasks


@router.get("/cases/{case_id}/tasks", response_model=list[TaskOut])
def list_tasks(case_id: uuid.UUID, db: Session = Depends(get_db)):
    if not db.get(Case, case_id):
        raise HTTPException(404, "Case not found")
    return (
        db.query(ResponseTask)
        .filter(ResponseTask.case_id == case_id)
        .order_by(ResponseTask.id.asc())
        .all()
    )


@router.post("/cases/{case_id}/tasks", response_model=TaskOut, status_code=201)
def create_task(case_id: uuid.UUID, payload: TaskCreate, db: Session = Depends(get_db)):
    if not db.get(Case, case_id):
        raise HTTPException(404, "Case not found")
    task = ResponseTask(case_id=case_id, **payload.model_dump())
    db.add(task)
    audit(db, case_id, "task_created", payload.title, actor=payload.owner)
    db.commit()
    db.refresh(task)
    return task


@router.patch("/cases/{case_id}/tasks/{task_id}", response_model=TaskOut)
def update_task(
    case_id: uuid.UUID, task_id: int, payload: TaskUpdate, db: Session = Depends(get_db)
):
    task = db.get(ResponseTask, task_id)
    if not task or task.case_id != case_id:
        raise HTTPException(404, "Task not found")
    data = payload.model_dump(exclude_unset=True)
    status = data.pop("status", None)
    for key, value in data.items():
        setattr(task, key, value)
    if status is not None:
        mark_task_status(db, task, status)
    db.commit()
    db.refresh(task)
    return task


@router.get("/cases/{case_id}/iocs", response_model=list[IOCOut])
def list_iocs(case_id: uuid.UUID, db: Session = Depends(get_db)):
    if not db.get(Case, case_id):
        raise HTTPException(404, "Case not found")
    return db.query(IOC).filter(IOC.case_id == case_id).order_by(IOC.created_at.desc()).all()


@router.post("/cases/{case_id}/iocs", response_model=IOCOut, status_code=201)
def create_ioc(case_id: uuid.UUID, payload: IOCCreate, db: Session = Depends(get_db)):
    if not db.get(Case, case_id):
        raise HTTPException(404, "Case not found")
    data = payload.model_dump()
    if not data.get("recommended_response"):
        data["recommended_response"] = default_ioc_response(data["ioc_type"])
    ioc = IOC(case_id=case_id, **data)
    db.add(ioc)
    audit(db, case_id, "ioc_added", f"{data['ioc_type']}:{data['value']}")
    db.commit()
    db.refresh(ioc)
    return ioc


@router.patch("/cases/{case_id}/iocs/{ioc_id}", response_model=IOCOut)
def update_ioc(
    case_id: uuid.UUID, ioc_id: int, payload: IOCUpdate, db: Session = Depends(get_db)
):
    ioc = db.get(IOC, ioc_id)
    if not ioc or ioc.case_id != case_id:
        raise HTTPException(404, "IOC not found")
    data = payload.model_dump(exclude_unset=True)
    for key, value in data.items():
        setattr(ioc, key, value)
    if "status" in data:
        audit(db, case_id, "ioc_status", f"{ioc.value} → {data['status']}")
    db.commit()
    db.refresh(ioc)
    return ioc


@router.get("/cases/{case_id}/techniques", response_model=list[TechniqueOut])
def list_techniques(case_id: uuid.UUID, db: Session = Depends(get_db)):
    if not db.get(Case, case_id):
        raise HTTPException(404, "Case not found")
    return (
        db.query(TechniqueHit)
        .filter(TechniqueHit.case_id == case_id)
        .order_by(TechniqueHit.created_at.desc())
        .all()
    )


@router.post("/cases/{case_id}/techniques", response_model=TechniqueOut, status_code=201)
def create_technique(
    case_id: uuid.UUID, payload: TechniqueCreate, db: Session = Depends(get_db)
):
    if not db.get(Case, case_id):
        raise HTTPException(404, "Case not found")
    data = payload.model_dump()
    mitre_id, name, tactic = resolve_technique(
        db, case_id, data.get("mitre_id", ""), data.get("name", ""), data.get("tactic", "")
    )
    data["mitre_id"] = mitre_id
    data["name"] = name
    data["tactic"] = tactic
    hit = TechniqueHit(case_id=case_id, **data)
    db.add(hit)
    audit(db, case_id, "technique_added", f"{mitre_id} {name}")
    db.commit()
    db.refresh(hit)
    return hit


@router.get("/cases/{case_id}/response-summary", response_model=ResponseSummary)
def response_summary(case_id: uuid.UUID, db: Session = Depends(get_db)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    return build_response_summary(db, case)


@router.get("/cases/{case_id}/audit", response_model=list[AuditLogOut])
def list_audit(case_id: uuid.UUID, db: Session = Depends(get_db)):
    if not db.get(Case, case_id):
        raise HTTPException(404, "Case not found")
    return (
        db.query(AuditLog)
        .filter(AuditLog.case_id == case_id)
        .order_by(AuditLog.created_at.desc())
        .all()
    )


@router.get("/cases/{case_id}/reports/ir-handoff")
def ir_handoff_report(case_id: uuid.UUID, db: Session = Depends(get_db)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    md = ir_handoff_markdown(db, case)
    audit(db, case_id, "ir_handoff_export", "Generated IR handoff markdown")
    db.commit()
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="case-{case.case_id}-ir-handoff.md"'},
    )
