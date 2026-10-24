import uuid
from typing import Any
from fastapi import APIRouter, HTTPException, Depends, Response
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.session import get_db
from app.db.models.case import Case
from app.db.models.evidence import Evidence
from app.db.models.events import Event
from app.db.models.detection import Detection
from app.db.models.user import User
from app.schemas.report import ForensicReportResponse
from app.services.report import generate_forensic_report_data, render_report_html, render_report_pdf
from app.core.permissions import get_authorized_case

router = APIRouter(tags=["reports"])


def _compile_case_report(case_id: uuid.UUID | str, current_user: User, db: Session) -> dict[str, Any]:
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
        }
        for e in evidence_records
    ]

    event_dicts = [
        {
            "id": str(ev.id),
            "timestamp": ev.timestamp.isoformat() if hasattr(ev.timestamp, "isoformat") else str(ev.timestamp),
            "event_type": ev.event_type,
            "source": ev.source,
            "host": (ev.details or {}).get("host") or (ev.details or {}).get("Computer") or (ev.details or {}).get("computer") or (ev.details or {}).get("src_ip") or "unknown_host",
            "user": (ev.details or {}).get("user") or (ev.details or {}).get("username") or "SYSTEM",
            "action": (ev.details or {}).get("action") or (ev.details or {}).get("message") or ev.event_type,
            "severity": (ev.details or {}).get("severity") or "low",
            "is_attack_path": bool((ev.details or {}).get("is_attack_path")),
            "attack_phase": (ev.details or {}).get("attack_phase"),
            "src_ip": (ev.details or {}).get("source_ip") or (ev.details or {}).get("src_ip"),
            "dst_ip": (ev.details or {}).get("destination_ip") or (ev.details or {}).get("dst_ip"),
        }
        for ev in events
    ]

    detection_dicts = [
        {
            "rule_name": d.rule_name,
            "mitre_technique": d.mitre_technique or "T1059",
            "mitre_tactic": (d.rule_information or {}).get("tactic", "Execution"),
            "severity": d.severity.value if hasattr(d.severity, "value") else str(d.severity),
            "description": d.description,
        }
        for d in detections
    ]

    return generate_forensic_report_data(
        case_dict={"id": str(case.id), "name": case.name},
        evidence_list=evidence_list,
        events=event_dicts,
        detections=detection_dicts,
        generator_user=current_user,
    )


@router.post("/{case_id}/reports/generate", response_model=ForensicReportResponse)
@router.post("/{case_id}/generate", response_model=ForensicReportResponse)
@router.post("/cases/{case_id}/reports/generate", response_model=ForensicReportResponse)
@router.get("/{case_id}/reports/generate", response_model=ForensicReportResponse)
@router.get("/{case_id}/generate", response_model=ForensicReportResponse)
@router.get("/cases/{case_id}/reports/generate", response_model=ForensicReportResponse)
@router.get("/{case_id}/report", response_model=ForensicReportResponse)
@router.get("/{case_id}", response_model=ForensicReportResponse)
@router.get("/cases/{case_id}/report", response_model=ForensicReportResponse)
def generate_report(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    report_data = _compile_case_report(case_id, current_user, db)
    return report_data


@router.get("/{case_id}/reports/html", response_class=HTMLResponse)
@router.get("/{case_id}/html", response_class=HTMLResponse)
@router.get("/cases/{case_id}/reports/html", response_class=HTMLResponse)
@router.get("/cases/{case_id}/html", response_class=HTMLResponse)
def export_html(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
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
