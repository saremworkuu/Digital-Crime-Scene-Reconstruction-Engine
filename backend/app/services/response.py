import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.models import (
    AuditLog,
    Case,
    IOC,
    Playbook,
    ResponseTask,
    TechniqueHit,
    TimelineEvent,
)


IR_PHASES = ["identify", "contain", "eradicate", "recover", "lessons"]

# Production-oriented, condensed containment hints
IOC_RESPONSE_HINTS = {
    "ip": "Block FW → hunt connections",
    "domain": "Block DNS/proxy → hunt lookups",
    "hash": "Quarantine → hash-hunt endpoints",
    "user": "Disable account → revoke sessions",
    "host": "Isolate host → preserve volatile",
    "email": "Block sender → purge mailboxes",
    "url": "Block URL → check click telemetry",
}


def audit(
    db: Session, case_id: uuid.UUID, action: str, detail: str = "", actor: str = "system"
) -> None:
    db.add(AuditLog(case_id=case_id, actor=actor, action=action, detail=detail))


def default_ioc_response(ioc_type: str) -> str:
    return IOC_RESPONSE_HINTS.get(ioc_type, "Investigate and document containment decision")


def apply_playbook(db: Session, case: Case, playbook: Playbook, owner: str = "unassigned") -> list[ResponseTask]:
    created: list[ResponseTask] = []
    for step in playbook.steps:
        task = ResponseTask(
            case_id=case.id,
            playbook_step_id=step.id,
            phase=step.phase,
            title=step.title,
            guidance=step.guidance,
            recommended_action=step.recommended_action,
            owner=owner,
            status="todo",
        )
        db.add(task)
        created.append(task)

    # Case lifecycle status only: open | in_progress | closed
    if case.status == "open":
        case.status = "in_progress"

    audit(
        db,
        case.id,
        "apply_playbook",
        f"Applied playbook '{playbook.name}' ({len(created)} tasks)",
        actor=owner,
    )
    db.flush()
    return created


def build_response_summary(db: Session, case: Case) -> dict:
    tasks = db.query(ResponseTask).filter(ResponseTask.case_id == case.id).all()
    iocs = db.query(IOC).filter(IOC.case_id == case.id).all()
    techniques = db.query(TechniqueHit).filter(TechniqueHit.case_id == case.id).all()
    events = (
        db.query(TimelineEvent)
        .filter(TimelineEvent.case_id == case.id)
        .order_by(TimelineEvent.timestamp.asc())
        .all()
    )

    phase_progress = []
    for phase in IR_PHASES:
        phase_tasks = [t for t in tasks if t.phase == phase]
        total = len(phase_tasks)
        done = len([t for t in phase_tasks if t.status in ("done", "skipped")])
        percent = round((done / total) * 100, 1) if total else 0.0
        phase_progress.append(
            {"phase": phase, "total": total, "done": done, "percent": percent}
        )

    open_tasks = [t for t in tasks if t.status in ("todo", "in_progress")]
    completed = [t for t in tasks if t.status == "done"]

    ioc_counts: dict[str, int] = {}
    for ioc in iocs:
        ioc_counts[ioc.status] = ioc_counts.get(ioc.status, 0) + 1

    next_actions = sorted(
        open_tasks,
        key=lambda t: (IR_PHASES.index(t.phase) if t.phase in IR_PHASES else 99, t.id),
    )[:5]

    narrative = _narrative(case, events, techniques, iocs, tasks)

    return {
        "case": case,
        "phase_progress": phase_progress,
        "open_tasks": len(open_tasks),
        "completed_tasks": len(completed),
        "ioc_counts": ioc_counts,
        "technique_count": len(techniques),
        "next_actions": next_actions,
        "narrative": narrative,
    }


def _narrative(case, events, techniques, iocs, tasks) -> str:
    case_label = getattr(case, "case_id", None) or str(case.id)
    creator = getattr(case, "creator", None)
    created_by_label = getattr(creator, "username", None) or str(case.created_by)
    lines = [
        f"Incident: {case_label} — {case.title}",
        f"Status: {case.status}",
        f"Created by: {created_by_label}",
        "",
    ]
    if events:
        lines.append("Key timeline:")
        for ev in events[:8]:
            ts = ev.timestamp.isoformat() if isinstance(ev.timestamp, datetime) else str(ev.timestamp)
            flag = " [suspicious]" if ev.is_suspicious else ""
            lines.append(f"- {ts} | {ev.host or '-'} | {ev.summary}{flag}")
        lines.append("")
    if techniques:
        lines.append("ATT&CK techniques observed:")
        for t in techniques:
            lines.append(f"- {t.mitre_id} {t.name} ({t.tactic or 'tactic n/a'}, conf={t.confidence})")
        lines.append("")
    if iocs:
        lines.append("Indicators:")
        for ioc in iocs:
            lines.append(f"- [{ioc.ioc_type}] {ioc.value} — {ioc.status}")
        lines.append("")

    done = len([t for t in tasks if t.status == "done"])
    open_n = len([t for t in tasks if t.status in ("todo", "in_progress")])
    lines.append(f"Response progress: {done} completed, {open_n} open tasks.")
    residual = [i for i in iocs if i.status in ("observed", "monitoring")]
    if residual:
        lines.append(
            f"Residual risk: {len(residual)} IOC(s) still observed/monitoring — confirm containment."
        )
    else:
        lines.append("Residual risk: no observed/monitoring IOCs remaining.")
    return "\n".join(lines)


def mark_task_status(db: Session, task: ResponseTask, status: str, actor: str = "analyst") -> ResponseTask:
    task.status = status
    if status == "done":
        task.completed_at = datetime.now(timezone.utc)
    elif status in ("todo", "in_progress", "skipped"):
        if status != "done":
            task.completed_at = None
    audit(db, task.case_id, "task_status", f"Task #{task.id} → {status}: {task.title}", actor=actor)
    return task


def ir_handoff_markdown(db: Session, case: Case) -> str:
    summary = build_response_summary(db, case)
    label = getattr(case, "case_id", None) or f"#{case.id}"
    notes_header = f"# IR Handoff Report — {label}\n\n"
    body = summary["narrative"]
    progress_lines = ["", "## Phase checklist", ""]
    for p in summary["phase_progress"]:
        progress_lines.append(
            f"- **{p['phase'].title()}**: {p['done']}/{p['total']} ({p['percent']}%)"
        )
    next_lines = ["", "## Next actions", ""]
    if summary["next_actions"]:
        for t in summary["next_actions"]:
            next_lines.append(f"- [{t.phase}] {t.title} (owner: {t.owner})")
    else:
        next_lines.append("- No open response tasks.")
    return notes_header + body + "\n" + "\n".join(progress_lines) + "\n" + "\n".join(next_lines) + "\n"
