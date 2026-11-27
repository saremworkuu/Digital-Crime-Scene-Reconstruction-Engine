import json
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.core.permissions import get_authorized_case
from app.db.session import get_db
from app.db.models.case import Case
from app.db.models.evidence import Evidence
from app.db.models.events import Event
from app.db.models.detection import Detection
from app.db.models.detection_event import DetectionEvent
from app.db.models.report import Report
from app.db.models.user import User
from app.schemas.report import ForensicReportResponse
from app.schemas.events import EventResponse
from app.services.report import (
    generate_forensic_report_data,
    is_container_evidence,
    render_report_html,
    render_report_pdf,
)
from app.services.event_ordering import sort_events
from app.services.audit import log_audit_event
from app.services.detection_engine import execute_detections_on_events
from app.services.detection import (
    detect_repeated_failed_logins,
    detect_failed_then_successful_login,
    detect_privilege_escalation,
    detect_lateral_movement,
    detect_web_sql_injection,
    detect_data_exfiltration,
    detect_dns_tunneling,
)

router = APIRouter(tags=["reports"])


def _iso_utc(val: Any) -> str | None:
    if val is None:
        return None
    if hasattr(val, "isoformat"):
        dt = val if val.tzinfo else val.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(val)


def _get_case_snapshot(case_id: uuid.UUID, db: Session) -> dict[str, Any]:
    ev_rows = db.execute(select(Evidence).where(Evidence.case_id == case_id)).scalars().all()
    ev_count = sum(1 for row in ev_rows if not is_container_evidence(row))
    case_events = sort_events(
        db.execute(select(Event).where(Event.case_id == case_id)).scalars().all()
    )
    evt_count = len(case_events)
    det_count = int(
        db.execute(select(func.count(Detection.id)).where(Detection.case_id == case_id)).scalar() or 0
    )
    last_ev = case_events[-1] if case_events else None
    last_det = db.execute(
        select(Detection.id, Detection.detected_at)
        .where(Detection.case_id == case_id)
        .order_by(Detection.detected_at.desc(), Detection.id.desc())
        .limit(1)
    ).first()
    return {
        "evidence_count": ev_count,
        "event_count": evt_count,
        "detection_count": det_count,
        "latest_event_id": str(last_ev.id) if last_ev else None,
        "latest_event_timestamp": _iso_utc(last_ev.timestamp) if last_ev else None,
        "latest_detection_id": str(last_det.id) if last_det else None,
        "latest_detection_timestamp": _iso_utc(last_det.detected_at) if last_det else None,
    }


def _is_report_stale(report_data: dict[str, Any], live_snapshot: dict[str, Any]) -> bool:
    saved_snap = report_data.get("case_snapshot")
    if isinstance(saved_snap, dict):
        keys = (
            "evidence_count",
            "event_count",
            "detection_count",
            "latest_event_id",
            "latest_event_timestamp",
            "latest_detection_id",
            "latest_detection_timestamp",
        )
        return any(saved_snap.get(k) != live_snapshot.get(k) for k in keys)

    manifest = report_data.get("evidence_manifest") or report_data.get("evidence_inventory") or []
    if len(manifest) != live_snapshot["evidence_count"]:
        return True
    if live_snapshot["detection_count"] > len(report_data.get("mitre_coverage") or []):
        return True
    if live_snapshot["event_count"] > 0 and (
        "0 normalized events were analyzed" in str(report_data.get("executive_summary") or "")
        or sum(int(e.get("event_count") or 0) for e in manifest) == 0
    ):
        return True
    return False


def _annotate_staleness(report_data: dict[str, Any], case_id: str, db: Session) -> dict[str, Any]:
    try:
        cid = uuid.UUID(str(case_id))
    except ValueError:
        return {**report_data, "stale": False}
    live_snap = _get_case_snapshot(cid, db)
    return {**report_data, "stale": _is_report_stale(report_data, live_snap)}


def _audit_report_action(db: Session, user: User, case_id: uuid.UUID | str, action: str,
                         request: Request | None = None, report_id: str | None = None,
                         details: dict[str, Any] | None = None) -> None:
    """Append one report audit event; audit entries are never updated or removed."""
    log_audit_event(
        db, user, action, f"report:{report_id or case_id}", request=request,
        case_id=uuid.UUID(str(case_id)), details={"report_id": report_id, **(details or {})},
    )
    db.commit()


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

    # Reconcile detections against the case's current event set before using
    # them. This also removes stale findings without changing evidence upload
    # or report-history behavior.
    from app.api.v1.detections import _execute_case_detections
    _execute_case_detections(case.id, db)

    evidence_records = db.execute(
        select(Evidence).where(Evidence.case_id == case.id)
    ).scalars().all()

    events = sort_events(
        db.execute(
            select(Event).where(Event.case_id == case.id).order_by(Event.timestamp.asc(), Event.id.asc())
        ).scalars().all()
    )
    valid_event_ids = {str(event.id) for event in events}

    detections = db.execute(
        select(Detection).where(Detection.case_id == case.id).order_by(Detection.detected_at.asc(), Detection.id.asc())
    ).scalars().all()

    detection_ids = [d.id for d in detections]
    associated_events: dict[str, set[str]] = {}
    if detection_ids:
        associations = db.execute(
            select(DetectionEvent.detection_id, DetectionEvent.event_id)
            .where(DetectionEvent.detection_id.in_(detection_ids))
        ).all()
        for detection_id, event_id in associations:
            associated_events.setdefault(str(detection_id), set()).add(str(event_id))

    # Legacy Detection rows may predate DetectionEvent links. Re-run the
    # existing deterministic detectors in memory only for unmapped rows, and
    # use their event IDs to recover report timestamps and timeline coverage.
    missing_links = [
        d for d in detections
        if not any(str(event_id) in valid_event_ids for event_id in ((d.rule_information or {}).get("matching_event_ids") or []))
        and not (associated_events.get(str(d.id), set()) & valid_event_ids)
    ]
    reconstructed_links: dict[str, set[str]] = {}
    if missing_links:
        reconstructed_findings = []
        try:
            reconstructed_findings.extend(execute_detections_on_events(events, case.id))
        except Exception:
            pass
        for detector in (
            detect_repeated_failed_logins,
            detect_failed_then_successful_login,
            detect_privilege_escalation,
            detect_lateral_movement,
            detect_web_sql_injection,
            detect_data_exfiltration,
            detect_dns_tunneling,
        ):
            try:
                reconstructed_findings.extend(detector(events))
            except Exception:
                continue
        for finding in reconstructed_findings:
            keys = {
                str(finding.get("rule_id") or "").casefold(),
                str(finding.get("rule_name") or "").casefold(),
            } - {""}
            event_ids = {str(event_id) for event_id in (finding.get("matching_event_ids") or []) if event_id}
            for key in keys:
                reconstructed_links.setdefault(key, set()).update(event_ids)

    verification_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    event_count_by_evidence: dict[uuid.UUID, int] = {}
    for ev in events:
        if ev.evidence_id is not None:
            event_count_by_evidence[ev.evidence_id] = event_count_by_evidence.get(ev.evidence_id, 0) + 1

    # Map uploader_id -> User.username so report identity matches audit log user_name.
    uploader_ids = {e.uploaded_by for e in evidence_records if e.uploaded_by is not None}
    uploader_map: dict[uuid.UUID, str] = {}
    if uploader_ids:
        for u in db.execute(select(User).where(User.id.in_(uploader_ids))).scalars().all():
            if getattr(u, "username", None):
                uploader_map[u.id] = u.username

    # Map evidence_id -> parsed_at & received_at from audit_log (read-only lookup).
    from app.db.models.audit_log import AuditLog
    from app.services.audit import format_audit_timestamp_iso
    upload_time_by_ev: dict[str, str] = {}
    parsed_time_by_ev: dict[str, str] = {}
    audit_rows = db.execute(
        select(AuditLog).where(AuditLog.case_id == case.id)
    ).scalars().all()
    for al in audit_rows:
        res_id = str(al.resource or "")
        if not res_id.startswith("evidence:"):
            continue
        ev_key = res_id.split(":", 1)[1]
        ts_iso = format_audit_timestamp_iso(al.timestamp)
        act = str(al.action or "").lower()
        if act in ("evidence.uploaded", "evidence_uploaded") and ts_iso:
            upload_time_by_ev.setdefault(ev_key, ts_iso)
        elif act in ("evidence.parsed", "evidence_parsed") and ts_iso:
            parsed_time_by_ev[ev_key] = ts_iso

    evidence_list = []
    for e in evidence_records:
        path = Path(e.file_path)
        if not path.is_absolute():
            path = Path.cwd() / path
        try:
            hasher = hashlib.sha256()
            with path.open("rb") as fh:
                while chunk := fh.read(1024 * 1024):
                    hasher.update(chunk)
            actual_hash = hasher.hexdigest()
            hash_status = "verified now: match" if actual_hash.casefold() == str(e.sha256_hash or "").casefold() else "verified now: MISMATCH"
        except OSError:
            hash_status = "verified now: unavailable"
        ev_key = str(e.id)
        db_up_iso = format_audit_timestamp_iso(e.uploaded_at) if e.uploaded_at else None
        received_iso = upload_time_by_ev.get(ev_key) or db_up_iso
        uploader_name = (
            uploader_map.get(e.uploaded_by)
            or getattr(e, "uploader_name", None)
            or (str(e.uploaded_by) if e.uploaded_by else "Unattributed")
        )
        event_count_for_item = event_count_by_evidence.get(e.id, 0)
        evidence_list.append({
            "filename": e.filename,
            "sha256_hash": e.sha256_hash,
            "size_bytes": e.file_size,
            "hash_status": hash_status,
            "hash_verified_at": verification_time,
            "event_count": event_count_for_item,
            "uploaded_at": received_iso,
            "received_at": received_iso,
            "parsed_at": parsed_time_by_ev.get(ev_key),
            "uploader_name": uploader_name,
            "parser_used": getattr(e, "parser_used", None),
            "is_container": is_container_evidence(e, event_count_for_item),
        })

    event_dicts = []
    for ev in events:
        canonical = EventResponse.model_validate(ev)
        event_dicts.append({
            "id": str(ev.id),
            "timestamp": ev.timestamp.isoformat() if hasattr(ev.timestamp, "isoformat") else str(ev.timestamp),
            "timestamp_timezone_known": canonical.timestamp_timezone_known,
            "event_type": ev.event_type,
            "source": ev.source,
            "source_file": canonical.source_file or ev.source,
            "host": canonical.host or "unknown_host",
            "user": canonical.user or "unknown",
            "action": canonical.action or ev.event_type,
            "severity": canonical.severity or "low",
            "is_attack_path": bool((ev.details or {}).get("is_attack_path")),
            "attack_phase": (ev.details or {}).get("attack_phase"),
            "src_ip": canonical.src_ip,
            "dst_ip": canonical.dst_ip,
            "evidence_id": str(ev.evidence_id) if ev.evidence_id else None,
            "fingerprint": getattr(ev, "fingerprint", None),
            "source_record_id": (ev.details or {}).get("source_record_id") or (ev.details or {}).get("record_id") or (ev.details or {}).get("event_record_id"),
            "details": ev.details or {},
        })
    events_by_id = {event["id"]: event for event in event_dicts if event.get("id")}

    detection_dicts = []
    for d in detections:
        rule_info = d.rule_information or {}
        matching_ids = {
            str(event_id)
            for event_id in (rule_info.get("matching_event_ids") or [])
            if str(event_id) in valid_event_ids
        }
        matching_ids.update(associated_events.get(str(d.id), set()) & valid_event_ids)
        if not matching_ids:
            matching_ids.update(reconstructed_links.get(str(d.rule_id or "").casefold(), set()))
            matching_ids.update(reconstructed_links.get(str(d.rule_name or "").casefold(), set()))
        matching_event_times = sorted(
            events_by_id[event_id]["timestamp"]
            for event_id in matching_ids
            if event_id in events_by_id
        )
        # Only timestamp linked events here. Legacy metadata may contain a
        # detection/upload time and must not be presented as event time.
        first_seen = matching_event_times[0] if matching_event_times else None
        last_seen = matching_event_times[-1] if matching_event_times else None
        if first_seen is None:
            continue
        detection_dicts.append({
            "id": str(d.id),
            "rule_id": d.rule_id,
            "rule_name": d.rule_name,
            "mitre_technique": d.mitre_technique or "T1059",
            "mitre_tactic": rule_info.get("tactic") or ("Exfiltration" if d.mitre_technique == "T1041" else "Execution"),
            "severity": d.severity.value if hasattr(d.severity, "value") else str(d.severity),
            "description": d.description,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "user": rule_info.get("user"),
            "actor": rule_info.get("actor"),
            "actor_role": rule_info.get("actor_role"),
            "target_host": rule_info.get("target_host") or rule_info.get("host"),
            "target_role": rule_info.get("target_role"),
            "src_ip": rule_info.get("src_ip"),
            "dst_ip": rule_info.get("dst_ip"),
            "rule_information": rule_info,
            "matching_event_ids": sorted(matching_ids),
            "source_file_references": sorted({
                str(events_by_id[event_id].get("source_file") or events_by_id[event_id].get("source") or "")
                for event_id in matching_ids if events_by_id.get(event_id)
            } - {""}),
        })

    last_ev = events[-1] if events else None
    last_det = detections[-1] if detections else None
    snapshot = {
        "evidence_count": sum(1 for item in evidence_list if not item.get("is_container")),
        "event_count": len(events),
        "detection_count": len(detections),
        "latest_event_id": str(last_ev.id) if last_ev else None,
        "latest_event_timestamp": _iso_utc(last_ev.timestamp) if last_ev else None,
        "latest_detection_id": str(last_det.id) if last_det else None,
        "latest_detection_timestamp": _iso_utc(last_det.detected_at) if last_det else None,
    }

    return generate_forensic_report_data(
        case_dict={"id": str(case.id), "name": case.name},
        evidence_list=evidence_list,
        events=event_dicts,
        detections=detection_dicts,
        generator_user=current_user,
        version=version,
        analysis_ran=(len(events) > 0),
        case_snapshot=snapshot,
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


def _latest_saved_report_with_id(case_id: uuid.UUID | str, db: Session) -> tuple[uuid.UUID | None, dict[str, Any] | None]:
    try:
        cid = uuid.UUID(str(case_id))
    except ValueError:
        return None, None

    latest = db.execute(
        select(Report.id, Report.report_data, Report.content)
        .where(Report.case_id == cid)
        .order_by(Report.generated_at.desc())
    ).first()
    if not latest:
        return None, None

    raw = latest.report_data or latest.content or "{}"
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        data = {}
    return (latest.id, data) if data else (None, None)


def _latest_saved_report_data(case_id: uuid.UUID | str, db: Session) -> dict[str, Any] | None:
    _, data = _latest_saved_report_with_id(case_id, db)
    return data


# ===========================================================================
# POST  — generate, save, return
# ===========================================================================
@router.post("/{case_id}/reports/generate", response_model=ForensicReportResponse)
@router.post("/{case_id}/generate", response_model=ForensicReportResponse)
@router.post("/cases/{case_id}/reports/generate", response_model=ForensicReportResponse)
def generate_report(
    case_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate a new forensic report, persist it to the reports table, and return it."""
    next_ver = _next_version(case_id, db)
    report_data = _compile_case_report(case_id, current_user, db, version=next_ver)
    saved = _save_report(case_id, report_data, db)
    _audit_report_action(db, current_user, case_id, "report.generated", request, str(saved.id), {"version": report_data.get("version")})
    return {**report_data, "stale": False}


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
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Convenience GET: compile and return current report (also saves a version).
    The client should prefer POST /generate to create a new saved version.
    """
    # Return latest saved if it exists; otherwise generate + save
    latest_id, latest_data = _latest_saved_report_with_id(case_id, db)
    if latest_data:
        _audit_report_action(db, current_user, case_id, "report.viewed", request, str(latest_id) if latest_id else None)
        return _annotate_staleness(latest_data, case_id, db)

    next_ver = _next_version(case_id, db)
    report_data = _compile_case_report(case_id, current_user, db, version=next_ver)
    saved = _save_report(case_id, report_data, db)
    cid = uuid.UUID(str(case_id))
    log_audit_event(
        db, current_user, "report.generated", f"report:{saved.id}", request=request,
        case_id=cid, details={"report_id": str(saved.id), "version": report_data.get("version")},
    )
    log_audit_event(
        db, current_user, "report.viewed", f"report:{saved.id}", request=request,
        case_id=cid, details={"report_id": str(saved.id)},
    )
    db.commit()
    return {**report_data, "stale": False}


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
        select(
            Report.id,
            Report.case_id,
            Report.title,
            Report.version,
            Report.generator_name,
            Report.generated_at,
        )
        .where(Report.case_id == cid)
        .order_by(Report.generated_at.desc())
    ).all()

    return [
        {
            "id": str(r.id),
            "case_id": str(r.case_id),
            "title": r.title,
            "version": r.version or "1.0",
            "generator_name": r.generator_name or "Lead Forensics Investigator",
            "generated_at": r.generated_at.isoformat() if hasattr(r.generated_at, "isoformat") else str(r.generated_at),
        }
        for r in rows
    ]


# ===========================================================================
# GET a specific saved version — HTML
# ===========================================================================
@router.get("/{case_id}/reports/{report_id}/data", response_model=ForensicReportResponse)
@router.get("/cases/{case_id}/reports/{report_id}/data", response_model=ForensicReportResponse)
def get_saved_report(
    case_id: str,
    report_id: str,
    request: Request,
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
    _audit_report_action(db, current_user, case_id, "report.viewed", request, str(row.id))
    return _annotate_staleness(data, case_id, db)


@router.delete("/{case_id}/reports/{report_id}")
@router.delete("/cases/{case_id}/reports/{report_id}")
def delete_saved_report(
    case_id: str,
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_authorized_case(case_id=case_id, current_user=current_user, db=db, allow_viewer=False)
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
    db.delete(row)
    db.commit()
    return {"message": "Saved report deleted successfully"}


@router.get("/{case_id}/reports/{report_id}/html", response_class=HTMLResponse)
@router.get("/cases/{case_id}/reports/{report_id}/html", response_class=HTMLResponse)
def download_saved_html(
    case_id: str,
    report_id: str,
    request: Request,
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

    rendered = render_report_html(_annotate_staleness(data, case_id, db))
    _audit_report_action(
        db,
        current_user,
        case_id,
        "report.downloaded",
        request,
        str(row.id),
        {
            "report_id": str(row.id),
            "version": data.get("version") or getattr(row, "version", None),
            "report_hash": data.get("report_hash"),
            "format": "html",
        },
    )
    return HTMLResponse(content=rendered)


# ===========================================================================
# GET a specific saved version — PDF
# ===========================================================================
@router.get("/{case_id}/reports/{report_id}/pdf")
@router.get("/cases/{case_id}/reports/{report_id}/pdf")
def download_saved_pdf(
    case_id: str,
    report_id: str,
    request: Request,
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

    pdf_bytes = render_report_pdf(_annotate_staleness(data, case_id, db))
    _audit_report_action(
        db,
        current_user,
        case_id,
        "report.downloaded",
        request,
        str(row.id),
        {
            "report_id": str(row.id),
            "version": data.get("version") or getattr(row, "version", None),
            "report_hash": data.get("report_hash"),
            "format": "pdf",
        },
    )
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
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    report_data = _latest_saved_report_data(case_id, db)
    if report_data is None:
        report_data = _compile_case_report(case_id, current_user, db)
        report_data = {**report_data, "stale": False}
    else:
        report_data = _annotate_staleness(report_data, case_id, db)
    html_content = render_report_html(report_data)
    _audit_report_action(
        db,
        current_user,
        case_id,
        "report.exported",
        request,
        str(report_data.get("id") or "") or None,
        details={
            "report_id": report_data.get("id"),
            "version": report_data.get("version"),
            "report_hash": report_data.get("report_hash"),
            "format": "html",
        },
    )
    return HTMLResponse(content=html_content)


@router.get("/{case_id}/reports/pdf")
@router.get("/{case_id}/pdf")
@router.get("/cases/{case_id}/reports/pdf")
@router.get("/cases/{case_id}/pdf")
def export_pdf(
    case_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    report_data = _latest_saved_report_data(case_id, db)
    if report_data is None:
        report_data = _compile_case_report(case_id, current_user, db)
        report_data = {**report_data, "stale": False}
    else:
        report_data = _annotate_staleness(report_data, case_id, db)
    pdf_bytes = render_report_pdf(report_data)
    _audit_report_action(
        db,
        current_user,
        case_id,
        "report.exported",
        request,
        str(report_data.get("id") or "") or None,
        details={
            "report_id": report_data.get("id"),
            "version": report_data.get("version"),
            "report_hash": report_data.get("report_hash"),
            "format": "pdf",
        },
    )
    clean_name = report_data.get("case_name", "incident").replace(" ", "_").lower()
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="forensic_report_{clean_name}_{str(case_id)[:8]}.pdf"'
        },
    )
