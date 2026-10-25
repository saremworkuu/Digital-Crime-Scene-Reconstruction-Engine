import uuid
import json
import re
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.models.case import Case
from app.db.models.detection import Detection, DetectionSeverity
from app.db.models.detection_event import DetectionEvent
from app.db.models.events import Event
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.detection import DetectionResponse, FalsePositiveRequest, DetectionRuleResponse
from app.services.graph import extract_event_fields
from app.services.detection import (
    detect_repeated_failed_logins,
    detect_failed_then_successful_login,
    detect_privilege_escalation,
    detect_lateral_movement,
    detect_web_sql_injection,
    detect_data_exfiltration,
    detect_dns_tunneling,
    detect_macro_attachment_delivery,
    detect_smb_lateral_movement,
    detect_periodic_beaconing,
)
from app.services.rule_loader import load_all_rules
from app.services.audit import log_audit_event
from app.services.report_fixes import canonical_title, unique_users
from app.core.permissions import get_authorized_case

router = APIRouter()


def _severity_rank(value) -> int:
    """Order finding severities when overlapping rules are coalesced."""
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
        str(getattr(value, "value", value) or "").lower(), 0
    )


def build_detection_response(db: Session, detection: Detection) -> DetectionResponse:
    event_ids = db.execute(
        select(DetectionEvent.event_id).join(Event, Event.id == DetectionEvent.event_id).where(
            DetectionEvent.detection_id == detection.id,
            Event.case_id == detection.case_id,
        )
    ).scalars().all()

    rule_info = detection.rule_information or {}
    matched_events = db.execute(
        select(Event).where(
            Event.case_id == detection.case_id,
            Event.id.in_(event_ids),
        ).order_by(Event.timestamp.asc())
    ).scalars().all() if event_ids else []
    event_time = matched_events[0].timestamp if matched_events else None
    if event_time and event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)
    ts_str = event_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if event_time else None
    observed_hosts = set(rule_info.get("hosts") or [])
    observed_hosts.update(value for value in (rule_info.get("host"), rule_info.get("target_host")) if value)
    observed_hosts.update(
        fields["host"] for fields in (extract_event_fields(event) for event in matched_events)
        if fields.get("host") and fields["host"].casefold() not in {"unknown", "unknown_host", "-"}
    )


def _coalesce_findings_by_host(findings: List[dict], events: List[Event]) -> List[dict]:
    """Merge corroborating source findings only when their observed host scope matches."""
    events_by_id = {str(event.id): event for event in events}

    def context(finding: dict):
        hosts = set()
        timestamps = []
        info = finding.get("rule_information") or {}
        for value in (
            finding.get("host"), finding.get("target_host"), info.get("host"),
            info.get("target_host"), *(info.get("hosts") or []), *(info.get("target_hosts") or []),
        ):
            if value and str(value).casefold() not in {"unknown", "unknown_host", "-"}:
                hosts.add(str(value).strip().casefold())
        event_ids = {str(value) for value in (finding.get("matching_event_ids") or [])}
        for event_id in event_ids:
            event = events_by_id.get(event_id)
            if event is None:
                continue
            fields = extract_event_fields(event)
            host = fields.get("host") or fields.get("workstation")
            if host and host.casefold() not in {"unknown", "unknown_host", "-"}:
                hosts.add(host.strip().casefold())
            if event.timestamp:
                timestamp = event.timestamp
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                timestamps.append(timestamp.astimezone(timezone.utc))
        words = {
            word for word in re.findall(r"[a-z0-9]+", str(finding.get("rule_name") or "").casefold())
            if word not in {"the", "via", "with", "or", "and", "of", "by", "from", "to", "a", "an"}
        }
        return hosts, timestamps, words, event_ids

    merged: List[dict] = []
    for finding in findings:
        hosts, times, words, event_ids = context(finding)
        technique = str(finding.get("mitre_technique") or "")
        tactic = str(finding.get("mitre_tactic") or (finding.get("rule_information") or {}).get("tactic") or "")
        title = canonical_title(finding.get("rule_name") or finding.get("rule_id")).casefold()

        def is_same_behavior(existing: dict) -> bool:
            old_hosts, old_times, old_words, old_ids = context(existing)
            if not hosts or hosts != old_hosts:
                return False
            if title == canonical_title(existing.get("rule_name") or existing.get("rule_id")).casefold():
                if event_ids & old_ids:
                    return True
                if times and old_times:
                    return min(abs((left - right).total_seconds()) for left in times for right in old_times) <= 60
            old_technique = str(existing.get("mitre_technique") or "")
            old_tactic = str(existing.get("mitre_tactic") or (existing.get("rule_information") or {}).get("tactic") or "")
            if not technique or technique != old_technique or tactic != old_tactic:
                return False
            if event_ids & old_ids:
                return True
            return bool(
                times and old_times
                and min(abs((left - right).total_seconds()) for left in times for right in old_times) <= 60
                and len(words & old_words) >= 2
            )

        duplicate = next((item for item in merged if is_same_behavior(item)), None)
        if duplicate is None:
            finding["rule_information"] = dict(finding.get("rule_information") or {})
            if hosts:
                finding["rule_information"]["hosts"] = sorted(hosts)
            merged.append(finding)
            continue

        duplicate_ids = set(map(str, duplicate.get("matching_event_ids") or [])) | event_ids
        duplicate["matching_event_ids"] = sorted(duplicate_ids)
        info = duplicate.setdefault("rule_information", {})
        info["hosts"] = sorted(hosts)
        incoming = finding.get("rule_information") or {}
        techniques = info.setdefault("mitre_techniques_all", [duplicate.get("mitre_technique")] if duplicate.get("mitre_technique") else [])
        for technique_id in incoming.get("mitre_techniques_all") or [finding.get("mitre_technique")]:
            if technique_id and technique_id not in techniques:
                techniques.append(technique_id)
        duplicate["rule_name"] = canonical_title(duplicate.get("rule_name") or duplicate.get("rule_id"))
        for key in ("source_file_references", "source_record_references", "attachment_names", "domains"):
            values = info.get(key) or []
            incoming_values = incoming.get(key) or []
            if not isinstance(values, list): values = [values]
            if not isinstance(incoming_values, list): incoming_values = [incoming_values]
            if values or incoming_values:
                info[key] = sorted({str(value) for value in values + incoming_values if value})
        sources = info.setdefault("corroborating_rules", [])
        for name in (finding.get("rule_name"), finding.get("rule_id")):
            if name and name not in sources:
                sources.append(str(name))
        if _severity_rank(finding.get("severity")) > _severity_rank(duplicate.get("severity")):
            duplicate["severity"] = finding.get("severity")
    return merged
    existing_entities = rule_info.get("entities") or {}
    observed_users = unique_users([
        *(existing_entities.get("users") or []),
        *([rule_info.get("user")] if rule_info.get("user") else []),
    ])
    observed_ips = list(dict.fromkeys([
        *(existing_entities.get("ips") or []),
        *[value for value in (rule_info.get("src_ip"), rule_info.get("dst_ip"), rule_info.get("actor") if rule_info.get("actor_role") == "adversary_infrastructure" else None) if value],
    ]))

    return DetectionResponse(
        id=detection.id,
        case_id=detection.case_id,
        rule_id=detection.rule_id,
        rule_name=canonical_title(detection.rule_name),
        severity=detection.severity,
        description=detection.description,
        mitre_technique=detection.mitre_technique or "T1110",
        mitre_techniques_all=(rule_info.get("mitre_techniques_all") or [detection.mitre_technique] if detection.mitre_technique else []),
        mitre_tactic=rule_info.get("tactic") or ("Exfiltration" if detection.mitre_technique == "T1041" else "Execution"),
        rule_information=rule_info,
        is_false_positive=detection.is_false_positive,
        false_positive=detection.is_false_positive,
        false_positive_reason=rule_info.get("fp_reason"),
        detected_at=detection.detected_at,
        timestamp=ts_str,
        event_ids=event_ids,
        matched_event_ids=[str(eid) for eid in event_ids],
        entities_involved={**existing_entities, "hosts": sorted(observed_hosts), "users": observed_users, "ips": observed_ips},
    )


from app.services.detection_engine import (
    execute_detections_on_events,
    get_rule_coverage_matrix,
    BUILTIN_SIGMA_RULES,
)


def _execute_case_detections(case_id: uuid.UUID, db: Session) -> List[Detection]:
    events = db.execute(
        select(Event)
        .where(Event.case_id == case_id)
        .order_by(Event.timestamp.asc(), Event.id.asc())
    ).scalars().all()
    valid_ids = {event.id for event in events}

    # Preserve examiner false-positive decisions only when the exact finding
    # (rule, description, and matched evidence events) is still present.
    old_rows = db.execute(select(Detection).where(Detection.case_id == case_id)).scalars().all()
    old_review = {}
    for row in old_rows:
        linked = set(db.execute(
            select(DetectionEvent.event_id)
            .join(Event, Event.id == DetectionEvent.event_id)
            .where(DetectionEvent.detection_id == row.id, Event.case_id == case_id)
        ).scalars().all()) & valid_ids
        signature = (row.rule_id, row.description, tuple(sorted(map(str, linked))))
        old_review[signature] = (row.is_false_positive, dict(row.rule_information or {}))
    if old_rows:
        db.query(DetectionEvent).filter(DetectionEvent.detection_id.in_([row.id for row in old_rows])).delete(synchronize_session=False)
        db.query(Detection).filter(Detection.case_id == case_id).delete(synchronize_session=False)
        db.flush()

    findings = []
    # 1. Deterministic Sigma detection engine + correlation rules + EDR findings
    try:
        findings.extend(execute_detections_on_events(events, case_id))
    except Exception as e:
        import logging
        logging.warning("Error running detection engine: %s", e)

    # 2. Supporting heuristic rules
    for detector in (
        detect_repeated_failed_logins,
        detect_failed_then_successful_login,
        detect_privilege_escalation,
        detect_lateral_movement,
        detect_web_sql_injection,
        detect_data_exfiltration,
        detect_dns_tunneling,
        detect_macro_attachment_delivery,
        detect_smb_lateral_movement,
        detect_periodic_beaconing,
    ):
        try:
            findings.extend(detector(events))
        except Exception:
            pass

    findings = _coalesce_findings_by_host(findings, events)

    saved_detections = []
    for finding in findings:
        rule_id = finding.get("rule_id", finding.get("rule_name", "detection-rule"))
        description = finding["description"]

        matching_ids = set()
        for event_id in finding.get("matching_event_ids", []):
            try:
                matching_ids.add(uuid.UUID(str(event_id)))
            except Exception:
                pass
        matching_ids &= valid_ids
        if not matching_ids:
            continue

        sev_val = finding.get("severity", "medium").lower()
        try:
            sev_enum = DetectionSeverity(sev_val)
        except ValueError:
            sev_enum = DetectionSeverity.MEDIUM

        rule_info = finding.get("rule_information", {}) or {}
        rule_info["matching_event_ids"] = sorted(str(event_id) for event_id in matching_ids)
        if finding.get("mitre_tactic") and not rule_info.get("tactic"):
            rule_info["tactic"] = finding["mitre_tactic"]
        if finding.get("source"):
            rule_info["source"] = finding["source"]
        if finding.get("host"):
            rule_info["host"] = finding["host"]
        if finding.get("user"):
            rule_info["user"] = finding["user"]
        if finding.get("source_file"):
            rule_info["source_file"] = finding["source_file"]
        if finding.get("source_record_references"):
            rule_info["source_record_references"] = finding["source_record_references"]
        for key in ("actor", "actor_role", "target_host", "target_role", "src_ip", "dst_ip"):
            if finding.get(key) is not None:
                rule_info[key] = finding[key]
        if finding.get("first_seen"):
            rule_info["first_seen"] = str(finding["first_seen"])
        if finding.get("last_seen"):
            rule_info["last_seen"] = str(finding["last_seen"])

        detection = Detection(
                case_id=case_id,
                rule_id=rule_id,
                rule_name=finding.get("rule_name") or finding.get("display_name") or "Security Alert",
                severity=sev_enum,
                description=description,
                mitre_technique=finding.get("mitre_technique", "T1059"),
                rule_information=rule_info,
                is_false_positive=False,
            )
        signature = (rule_id, description, tuple(sorted(map(str, matching_ids))))
        if signature in old_review:
            was_fp, old_info = old_review[signature]
            detection.is_false_positive = was_fp
            for fp_key in ("fp_reason", "fp_marked_by", "fp_timestamp"):
                if fp_key in old_info:
                    rule_info[fp_key] = old_info[fp_key]
            detection.rule_information = rule_info
        db.add(detection)
        db.flush()
        for event_id in matching_ids:
            db.add(DetectionEvent(detection_id=detection.id, event_id=event_id))

        saved_detections.append(detection)

    db.commit()
    for d in saved_detections:
        db.refresh(d)
    return saved_detections


@router.post(
    "/cases/{case_id}/run",
    response_model=List[DetectionResponse],
)
def run_detection(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    case = get_authorized_case(case_id=case_id, current_user=current_user, db=db, allow_viewer=False)
    detections = _execute_case_detections(case.id, db)
    responses = [build_detection_response(db, d) for d in detections]
    return sorted(responses, key=lambda response: response.timestamp or "")


@router.get(
    "/cases/{case_id}/detections",
    response_model=List[DetectionResponse],
)
def get_case_detections(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    case = get_authorized_case(case_id=case_id, current_user=current_user, db=db, allow_viewer=True)

    detections = _execute_case_detections(case.id, db)

    return [build_detection_response(db, d) for d in detections]


@router.post("/{detection_id}/false-positive")
@router.post("/detections/{detection_id}/false-positive")
def toggle_false_positive(
    detection_id: uuid.UUID,
    payload: FalsePositiveRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    detection = db.get(Detection, detection_id)
    if detection is None:
        raise HTTPException(status_code=404, detail="Detection not found.")

    get_authorized_case(case_id=detection.case_id, current_user=current_user, db=db, allow_viewer=False)

    detection.is_false_positive = payload.false_positive
    info = detection.rule_information or {}
    if payload.reason:
        info["fp_reason"] = payload.reason
    info["fp_marked_by"] = current_user.username
    detection.rule_information = info

    log_audit_event(
        db=db,
        user=current_user,
        action="detection.false_positive_toggled",
        resource=f"detection:{detection.id}",
        request=request,
        case_id=detection.case_id,
        details={
            "rule_name": detection.rule_name,
            "false_positive": payload.false_positive,
            "reason": payload.reason,
        },
    )

    db.commit()
    db.refresh(detection)
    return build_detection_response(db, detection)


@router.get("/cases/{case_id}/coverage")
@router.get("/cases/{case_id}/detections/coverage")
def get_case_rule_coverage(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    case = get_authorized_case(case_id=case_id, current_user=current_user, db=db, allow_viewer=True)
    events = db.execute(
        select(Event)
        .where(Event.case_id == case.id)
        .order_by(Event.timestamp.asc(), Event.id.asc())
    ).scalars().all()
    findings = execute_detections_on_events(events, case.id)
    for detector in (detect_macro_attachment_delivery, detect_smb_lateral_movement, detect_periodic_beaconing):
        findings.extend(detector(events))
    return get_rule_coverage_matrix(findings)


@router.get("/rules", response_model=List[DetectionRuleResponse])
@router.get("/detections/rules", response_model=List[DetectionRuleResponse])
def get_detection_rules(
    current_user: User = Depends(get_current_user),
):
    raw_rules = load_all_rules()
    seen_ids = set()
    rule_responses = []

    for r in BUILTIN_SIGMA_RULES:
        seen_ids.add(r["id"])
        rule_responses.append(
            DetectionRuleResponse(
                id=r["id"],
                name=r["name"],
                severity=r["severity"],
                mitre_technique=r["mitre_technique"],
                mitre_tactic=r["mitre_tactic"],
                description=r["description"],
                author="DCSRE Forensics Core",
                status="active",
                tags=[r["mitre_tactic"].lower(), r["mitre_technique"].lower()],
                yaml_content=json.dumps(r["detection"], indent=2),
            )
        )

    for r in raw_rules:
        r_id = r.get("id", "rule")
        if r_id in seen_ids:
            continue
        rule_responses.append(
            DetectionRuleResponse(
                id=r_id,
                name=r.get("title", r.get("id")),
                severity=r.get("severity", "medium"),
                mitre_technique=r.get("mitre_technique", "T1059"),
                mitre_tactic=r.get("mitre_tactic", "Execution"),
                description=r.get("description", ""),
                author=r.get("author", "DCSRE Forensics Team"),
                status=r.get("status", "active"),
                tags=r.get("tags", []),
                yaml_content=r.get("yaml_content"),
            )
        )
    return rule_responses


@router.post("/rules/reload")
@router.post("/detections/rules/reload")
def reload_detection_rules(
    current_user: User = Depends(get_current_user),
):
    rules = load_all_rules()
    return {"message": f"Successfully reloaded {len(rules)} detection rules from disk."}


@router.get(
    "/",
    response_model=List[DetectionResponse],
)
def get_detections(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = select(Detection).join(Case, Detection.case_id == Case.id).where(Case.is_deleted.is_(False))
    if current_user.role != "admin":
        query = query.where(Case.created_by == current_user.id)

    detections = db.execute(query.order_by(Detection.detected_at.desc())).scalars().all()
    responses = []
    for detection in detections:
        response = build_detection_response(db, detection)
        if response.event_ids:
            responses.append(response)
    return sorted(responses, key=lambda response: response.timestamp or "", reverse=True)


@router.get(
    "/{detection_id}",
    response_model=DetectionResponse,
)
def get_detection(
    detection_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    detection = db.get(Detection, detection_id)
    if detection is None:
        raise HTTPException(status_code=404, detail="Detection not found.")

    get_authorized_case(case_id=detection.case_id, current_user=current_user, db=db, allow_viewer=True)
    return build_detection_response(db, detection)
