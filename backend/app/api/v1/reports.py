import json
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.core.permissions import get_authorized_case
from app.db.session import get_db
from app.db.models.case import Case
from app.db.models.evidence import Evidence
from app.db.models.events import Event
from app.db.models.detection import Detection
from app.db.models.report import Report
from app.db.models.user import User
from app.schemas.report import ForensicReportResponse
from app.services.report import generate_forensic_report_data, render_report_html, render_report_pdf

router = APIRouter(tags=["reports"])


# ---------------------------------------------------------------------------
# Internal helper: compile all case data and build the report dict
# ---------------------------------------------------------------------------
def _compile_case_report(
    case_id: uuid.UUID | str,
    current_user: User,
    db: Session,
    version: str = "1.0",
) -> dict[str, Any]:
    case = get_authorized_case(case_id=case_id, current_user=current_user, db=db, allow_viewer=True)

    evidence_records = db.execute(
        select(Evidence).where(Evidence.case_id == case.id)
    ).scalars().all()

    events = db.execute(
        select(Event).where(Event.case_id == case.id).order_by(Event.timestamp.asc())
    ).scalars().all()

    detections = db.execute(
        select(Detection).where(Detection.case_id == case.id)
    ).scalars().all()

    evidence_list = [
        {
            "filename": e.filename,
            "sha256_hash": e.sha256_hash,
            "size_bytes": e.file_size,
            "event_count": len([ev for ev in events if ev.evidence_id == e.id]),
            "uploaded_at": e.uploaded_at.isoformat() if hasattr(e.uploaded_at, "isoformat") else str(e.uploaded_at),
            "uploader_name": getattr(e, "uploader_name", None) or "Forensics Examiner",
        }
        for e in evidence_records
    ]

    event_dicts = [
        {
            "id": str(ev.id),
            "timestamp": ev.timestamp.isoformat() if hasattr(ev.timestamp, "isoformat") else str(ev.timestamp),
            "event_type": ev.event_type,
            "source": ev.source,
            "source_file": (ev.details or {}).get("source_file") or ev.source,
            "host": (
                (ev.details or {}).get("host")
                or (ev.details or {}).get("Computer")
                or (ev.details or {}).get("computer")
                or "unknown_host"
            ),
            "user": (ev.details or {}).get("user") or (ev.details or {}).get("username") or "SYSTEM",
            "action": (ev.details or {}).get("action") or (ev.details or {}).get("message") or ev.event_type,
            "severity": (ev.details or {}).get("severity") or "low",
            "is_attack_path": bool((ev.details or {}).get("is_attack_path")),
            "attack_phase": (ev.details or {}).get("attack_phase"),
            "src_ip": (ev.details or {}).get("source_ip") or (ev.details or {}).get("src_ip"),
            "dst_ip": (ev.details or {}).get("destination_ip") or (ev.details or {}).get("dst_ip"),
            "evidence_id": str(ev.evidence_id) if ev.evidence_id else None,
        }
        for ev in events
    ]
    events_by_id = {event["id"]: event for event in event_dicts if event.get("id")}

    detection_dicts = [
        {
            "id": str(d.id),
            "rule_id": d.rule_id,
            "rule_name": d.rule_name,
            "mitre_technique": d.mitre_technique or "T1059",
            "mitre_tactic": (d.rule_information or {}).get("tactic", "Execution"),
            "severity": d.severity.value if hasattr(d.severity, "value") else str(d.severity),
            "description": d.description,
            "first_seen": min(
                (
                    events_by_id[str(event_id)]["timestamp"]
                    for event_id in ((d.rule_information or {}).get("matching_event_ids") or [])
                    if str(event_id) in events_by_id
                ),
                default=d.detected_at.isoformat() if hasattr(d.detected_at, "isoformat") else str(d.detected_at),
            ),
            "last_seen": max(
                (
                    events_by_id[str(event_id)]["timestamp"]
                    for event_id in ((d.rule_information or {}).get("matching_event_ids") or [])
                    if str(event_id) in events_by_id
                ),
                default=d.detected_at.isoformat() if hasattr(d.detected_at, "isoformat") else str(d.detected_at),
            ),
            "user": (d.rule_information or {}).get("user"),
            "actor": (d.rule_information or {}).get("actor"),
            "actor_role": (d.rule_information or {}).get("actor_role"),
            "target_host": (d.rule_information or {}).get("target_host") or (d.rule_information or {}).get("host"),
            "target_role": (d.rule_information or {}).get("target_role"),
            "src_ip": (d.rule_information or {}).get("src_ip"),
            "matching_event_ids": (d.rule_information or {}).get("matching_event_ids") or [],
        }
        for d in detections
    ]

    return generate_forensic_report_data(
        case_dict={"id": str(case.id), "name": case.name},
        evidence_list=evidence_list,
        events=event_dicts,
        detections=detection_dicts,
        generator_user=current_user,
        version=version,
    )


# ---------------------------------------------------------------------------
# Helper: compute next version for this case
# ---------------------------------------------------------------------------
def _next_version(case_id: uuid.UUID | str, db: Session) -> str:
    """Returns the next version string: 1.0, 1.1, 1.2 ..."""
    try:
        cid = uuid.UUID(str(case_id))
    except ValueError:
        return "1.0"

    rows = db.execute(
        select(Report.version).where(Report.case_id == cid)
    ).scalars().all()

    if not rows:
        return "1.0"

    max_minor = 0
    for v in rows:
        try:
            parts = str(v or "1.0").split(".")
            minor = int(parts[1]) if len(parts) > 1 else 0
            if minor > max_minor:
                max_minor = minor
        except (ValueError, IndexError):
            pass
    return f"1.{max_minor + 1}"


# ---------------------------------------------------------------------------
# Helper: persist a report dict to the reports table
# ---------------------------------------------------------------------------
def _save_report(case_id: uuid.UUID | str, report_data: dict[str, Any], db: Session) -> Report:
    """Inserts a new Report row and returns it."""
    try:
        cid = uuid.UUID(str(case_id))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid case_id")

    title = f"Forensic Report v{report_data.get('version', '1.0')} — {report_data.get('case_name', '')}"
    content = json.dumps(report_data, default=str)

    report_row = Report(
        id=uuid.uuid4(),
        case_id=cid,
        title=title,
        content=content,
    )
    # Set optional columns added by migration
    if hasattr(report_row, "version"):
        report_row.version = str(report_data.get("version", "1.0"))
    if hasattr(report_row, "generator_name"):
        report_row.generator_name = str(report_data.get("generator_name", "Lead Forensics Investigator"))
    if hasattr(report_row, "report_data"):
        report_row.report_data = content

    db.add(report_row)
    db.commit()
    db.refresh(report_row)
    return report_row


# ---------------------------------------------------------------------------
# Helper: load saved report dict from DB
# ---------------------------------------------------------------------------
def _load_report_data(report_row: Report) -> dict[str, Any]:
    raw = getattr(report_row, "report_data", None) or report_row.content or "{}"
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


def _latest_saved_report_data(case_id: uuid.UUID | str, db: Session) -> dict[str, Any] | None:
    try:
        cid = uuid.UUID(str(case_id))
    except ValueError:
        return None

    latest = db.execute(
        select(Report)
        .where(Report.case_id == cid)
        .order_by(Report.generated_at.desc())
    ).scalars().first()
    if not latest:
        return None

    data = _load_report_data(latest)
    return data or None


# ===========================================================================
# POST  — generate, save, return
# ===========================================================================
@router.post("/{case_id}/reports/generate", response_model=ForensicReportResponse)
@router.post("/{case_id}/generate", response_model=ForensicReportResponse)
@router.post("/cases/{case_id}/reports/generate", response_model=ForensicReportResponse)
def generate_report(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate a new forensic report, persist it to the reports table, and return it."""
    next_ver = _next_version(case_id, db)
    report_data = _compile_case_report(case_id, current_user, db, version=next_ver)
    _save_report(case_id, report_data, db)
    return report_data


# ===========================================================================
# GET — generate (legacy GET compat) — always saves a new version
# ===========================================================================
@router.get("/{case_id}/reports/generate", response_model=ForensicReportResponse)
@router.get("/{case_id}/generate", response_model=ForensicReportResponse)
@router.get("/cases/{case_id}/reports/generate", response_model=ForensicReportResponse)
@router.get("/{case_id}/report", response_model=ForensicReportResponse)
@router.get("/{case_id}", response_model=ForensicReportResponse)
@router.get("/cases/{case_id}/report", response_model=ForensicReportResponse)
def get_report(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Convenience GET: compile and return current report (also saves a version).
    The client should prefer POST /generate to create a new saved version.
    """
    # Return latest saved if it exists; otherwise generate + save
    latest_data = _latest_saved_report_data(case_id, db)
    if latest_data:
        return latest_data

    next_ver = _next_version(case_id, db)
    report_data = _compile_case_report(case_id, current_user, db, version=next_ver)
    _save_report(case_id, report_data, db)
    return report_data


# ===========================================================================
# GET list of saved report versions for a case
# ===========================================================================
@router.get("/{case_id}/reports")
@router.get("/cases/{case_id}/reports")
def list_reports(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return the list of saved report versions for a case, newest first."""
    get_authorized_case(case_id=case_id, current_user=current_user, db=db, allow_viewer=True)

    try:
        cid = uuid.UUID(str(case_id))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid case_id")

    rows = db.execute(
        select(Report)
        .where(Report.case_id == cid)
        .order_by(Report.generated_at.desc())
    ).scalars().all()

    return [
        {
            "id": str(r.id),
            "case_id": str(r.case_id),
            "title": r.title,
            "version": getattr(r, "version", "1.0") or "1.0",
            "generator_name": getattr(r, "generator_name", None) or "Lead Forensics Investigator",
            "generated_at": r.generated_at.isoformat() if hasattr(r.generated_at, "isoformat") else str(r.generated_at),
        }
        for r in rows
    ]


# ===========================================================================
# GET a specific saved version — HTML
# ===========================================================================
@router.get("/{case_id}/reports/{report_id}/html", response_class=HTMLResponse)
@router.get("/cases/{case_id}/reports/{report_id}/html", response_class=HTMLResponse)
def download_saved_html(
    case_id: str,
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_authorized_case(case_id=case_id, current_user=current_user, db=db, allow_viewer=True)

    try:
        cid = uuid.UUID(str(case_id))
        rid = uuid.UUID(str(report_id))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid ID")

    row = db.execute(
        select(Report).where(Report.case_id == cid, Report.id == rid)
    ).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")

    data = _load_report_data(row)
    if not data:
        raise HTTPException(status_code=404, detail="Report content missing")

    return HTMLResponse(content=render_report_html(data))


# ===========================================================================
# GET a specific saved version — PDF
# ===========================================================================
@router.get("/{case_id}/reports/{report_id}/pdf")
@router.get("/cases/{case_id}/reports/{report_id}/pdf")
def download_saved_pdf(
    case_id: str,
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_authorized_case(case_id=case_id, current_user=current_user, db=db, allow_viewer=True)

    try:
        cid = uuid.UUID(str(case_id))
        rid = uuid.UUID(str(report_id))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid ID")

    row = db.execute(
        select(Report).where(Report.case_id == cid, Report.id == rid)
    ).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")

    data = _load_report_data(row)
    if not data:
        raise HTTPException(status_code=404, detail="Report content missing")

    pdf_bytes = render_report_pdf(data)
    ver = getattr(row, "version", "1.0") or "1.0"
    clean_name = data.get("case_name", "incident").replace(" ", "_").lower()
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="forensic_report_{clean_name}_v{ver}.pdf"'
        },
    )


# ===========================================================================
# GET current-version HTML and PDF (no saved version selection)
# ===========================================================================
@router.get("/{case_id}/reports/html", response_class=HTMLResponse)
@router.get("/{case_id}/html", response_class=HTMLResponse)
@router.get("/cases/{case_id}/reports/html", response_class=HTMLResponse)
@router.get("/cases/{case_id}/html", response_class=HTMLResponse)
def export_html(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    report_data = _latest_saved_report_data(case_id, db)
    if report_data is None:
        report_data = _compile_case_report(case_id, current_user, db)
    html_content = render_report_html(report_data)
    return HTMLResponse(content=html_content)


@router.get("/{case_id}/reports/pdf")
@router.get("/{case_id}/pdf")
@router.get("/cases/{case_id}/reports/pdf")
@router.get("/cases/{case_id}/pdf")
def export_pdf(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    report_data = _latest_saved_report_data(case_id, db)
    if report_data is None:
        report_data = _compile_case_report(case_id, current_user, db)
    pdf_bytes = render_report_pdf(report_data)
    clean_name = report_data.get("case_name", "incident").replace(" ", "_").lower()
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="forensic_report_{clean_name}_{str(case_id)[:8]}.pdf"'
        },
    )
