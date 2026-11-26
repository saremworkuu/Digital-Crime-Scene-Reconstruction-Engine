import uuid
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from app.core.permissions import require_admin
from app.db.session import get_db
from app.db.models.sigma_rule import SigmaRule
from app.db.models.user import User
from app.db.models.audit_log import AuditLog
from app.services.audit import log_audit_event
from app.schemas.admin import (
    AdminSigmaRuleResponse,
    AdminSigmaRuleCreateRequest,
    AdminSigmaRuleUpdateRequest,
    AdminSigmaRuleToggleRequest,
    AdminRuleTestResponse,
)

router = APIRouter(dependencies=[Depends(require_admin)])


def to_admin_rule_response(r: SigmaRule) -> AdminSigmaRuleResponse:
    created_str = r.created_at.isoformat() if hasattr(r.created_at, "isoformat") else str(r.created_at)
    return AdminSigmaRuleResponse(
        id=r.id,
        name=r.name,
        severity=r.severity,
        mitre_id=r.mitre_id,
        enabled=r.enabled,
        times_triggered=r.times_triggered,
        description=r.description,
        query=r.query,
        created_at=created_str,
    )


@router.get("", response_model=List[AdminSigmaRuleResponse])
@router.get("/", response_model=List[AdminSigmaRuleResponse])
def get_admin_rules(
    severity: Optional[str] = None,
    enabled: Optional[bool] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = select(SigmaRule).order_by(SigmaRule.created_at.desc())
    rules = db.execute(query).scalars().all()

    results = []
    for r in rules:
        if severity and severity != "all" and r.severity.lower() != severity.lower():
            continue
        if enabled is not None and r.enabled != enabled:
            continue
        if search:
            q = search.lower()
            if (
                q not in r.name.lower()
                and q not in r.mitre_id.lower()
                and q not in r.description.lower()
            ):
                continue

        results.append(to_admin_rule_response(r))

    return results


@router.post("/", response_model=AdminSigmaRuleResponse, status_code=status.HTTP_201_CREATED)
def create_admin_rule(
    data: AdminSigmaRuleCreateRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    rule_id = f"sig-{uuid.uuid4().hex[:6]}"
    new_rule = SigmaRule(
        id=rule_id,
        name=data.name,
        severity=data.severity,
        mitre_id=data.mitre_id,
        description=data.description,
        query=data.query,
        enabled=True,
        times_triggered=0,
    )
    db.add(new_rule)

    log_audit_event(
        db=db,
        user=current_admin,
        action="sigma_rule.created",
        resource=f"rule:{rule_id}",
        details={"name": data.name, "mitre_id": data.mitre_id, "severity": data.severity},
    )

    db.commit()
    db.refresh(new_rule)
    return to_admin_rule_response(new_rule)


@router.patch("/{rule_id}", response_model=AdminSigmaRuleResponse)
def update_admin_rule(
    rule_id: str,
    patch: AdminSigmaRuleUpdateRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    r = db.get(SigmaRule, rule_id)
    if not r:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found.")

    details = {}
    if patch.name is not None:
        r.name = patch.name
        details["name"] = patch.name
    if patch.severity is not None:
        r.severity = patch.severity
        details["severity"] = patch.severity
    if patch.mitre_id is not None:
        r.mitre_id = patch.mitre_id
        details["mitre_id"] = patch.mitre_id
    if patch.description is not None:
        r.description = patch.description
        details["description"] = patch.description
    if patch.query is not None:
        r.query = patch.query
        details["query"] = patch.query
    if patch.enabled is not None:
        r.enabled = patch.enabled
        details["enabled"] = patch.enabled

    log_audit_event(
        db=db,
        user=current_admin,
        action="sigma_rule.updated",
        resource=f"rule:{rule_id}",
        details=details,
    )

    db.commit()
    db.refresh(r)
    return to_admin_rule_response(r)


@router.patch("/{rule_id}/toggle", response_model=AdminSigmaRuleResponse)
def toggle_admin_rule(
    rule_id: str,
    body: AdminSigmaRuleToggleRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    r = db.get(SigmaRule, rule_id)
    if not r:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found.")

    r.enabled = body.enabled

    action_name = "sigma_rule.enabled" if body.enabled else "sigma_rule.disabled"
    log_audit_event(
        db=db,
        user=current_admin,
        action=action_name,
        resource=f"rule:{rule_id}",
        details={"name": r.name, "mitre_id": r.mitre_id, "enabled": body.enabled},
    )

    db.commit()
    db.refresh(r)
    return to_admin_rule_response(r)


@router.delete("/{rule_id}")
def delete_admin_rule(
    rule_id: str,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    r = db.get(SigmaRule, rule_id)
    if not r:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found.")

    rule_info = {"name": r.name, "mitre_id": r.mitre_id}
    db.delete(r)

    log_audit_event(
        db=db,
        user=current_admin,
        action="sigma_rule.deleted",
        resource=f"rule:{rule_id}",
        details=rule_info,
    )

    db.commit()
    return {"message": "Rule deleted successfully", "id": rule_id}


@router.post("/{rule_id}/test", response_model=AdminRuleTestResponse)
def test_admin_rule(
    rule_id: str,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    import re
    from app.db.models.events import Event

    r = db.get(SigmaRule, rule_id)
    if not r:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found.")

    quoted_terms = [q.lower().strip() for q in re.findall(r'"([^"]{2,})"', r.query or "") if q.strip()]
    fallback_terms = [
        tok.lower()
        for tok in re.split(r"[^A-Za-z0-9_.-]+", f"{r.name} {r.query}")
        if len(tok) >= 4 and tok.lower() not in {"contains", "regex", "and", "not", "true", "false", "rule", "sigma"}
    ]
    terms = quoted_terms or fallback_terms[:4]

    recent_events = db.execute(
        select(Event).order_by(Event.timestamp.desc()).limit(500)
    ).scalars().all()

    matches = []
    match_count = 0
    for ev in recent_events:
        details = ev.details if isinstance(ev.details, dict) else {}
        haystack = " ".join(
            [
                str(ev.event_type or ""),
                str(ev.source or ""),
                str(details.get("raw") or ""),
                str(details.get("command_line") or ""),
                str(details.get("process") or ""),
                str(details.get("action") or ""),
            ]
        ).lower()
        if terms and any(term in haystack for term in terms):
            match_count += 1
            if len(matches) < 10:
                host = str(details.get("host") or details.get("dst_ip") or details.get("src_ip") or ev.source or "unknown")
                snippet = str(
                    details.get("raw")
                    or details.get("command_line")
                    or f"{ev.event_type}: {details.get('action') or ''}".strip()
                )[:240]
                matches.append(
                    {
                        "timestamp": ev.timestamp.isoformat() if hasattr(ev.timestamp, "isoformat") else str(ev.timestamp),
                        "host": host,
                        "log_snippet": snippet,
                    }
                )

    r.times_triggered = match_count
    db.commit()

    return AdminRuleTestResponse(
        ruleId=rule_id,
        matchCount=match_count,
        sampleMatches=matches,
    )


@router.post("/import")
def import_admin_rules(
    rules: List[dict],
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    imported_count = 0
    for item in rules:
        name = item.get("name")
        mitre_id = item.get("mitre_id")
        if name and mitre_id:
            r_id = f"sig-{uuid.uuid4().hex[:6]}"
            new_r = SigmaRule(
                id=r_id,
                name=name,
                severity=item.get("severity", "medium"),
                mitre_id=mitre_id,
                description=item.get("description", ""),
                query=item.get("query", ""),
                enabled=item.get("enabled", True),
                times_triggered=0,
            )
            db.add(new_r)
            imported_count += 1

    log_audit_event(
        db=db,
        user=current_admin,
        action="sigma_rule.imported",
        resource="rules:bulk-import",
        details={"imported_count": imported_count},
    )

    db.commit()
    return {"importedCount": imported_count}
