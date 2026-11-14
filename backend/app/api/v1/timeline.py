import uuid
from datetime import datetime
import csv
import io
import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy import select, or_, func
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.models.case import Case
from app.db.models.events import Event
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.events import EventResponse
from app.core.permissions import get_authorized_case

router = APIRouter()


@router.get("/{case_id}", response_model=list[EventResponse])
@router.get("/cases/{case_id}/timeline", response_model=list[EventResponse])
def get_case_timeline(
    case_id: str,
    limit: int = Query(default=10000, ge=1, le=100000),
    offset: int = Query(default=0, ge=0),
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    host: str | None = Query(default=None),
    ip: str | None = Query(default=None),
    user: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    case = get_authorized_case(
        case_id=case_id,
        current_user=current_user,
        db=db,
        allow_viewer=True,
    )

    query = select(Event).where(Event.case_id == case.id)

    if start_time is not None:
        query = query.where(Event.timestamp >= start_time)

    if end_time is not None:
        query = query.where(Event.timestamp <= end_time)

    if host:
        pattern = f"%{host}%"
        query = query.where(
            or_(
                Event.source.ilike(pattern),
                Event.details["host"].astext.ilike(pattern),
                Event.details["computer"].astext.ilike(pattern),
            )
        )

    if ip:
        pattern = f"%{ip}%"
        query = query.where(
            or_(
                Event.details["source_ip"].astext.ilike(pattern),
                Event.details["ip"].astext.ilike(pattern),
            )
        )

    if user:
        pattern = f"%{user}%"
        query = query.where(
            or_(
                Event.details["username"].astext.ilike(pattern),
                Event.details["user"].astext.ilike(pattern),
            )
        )

    if severity:
        pattern = f"%{severity}%"
        query = query.where(
            Event.details["severity"].astext.ilike(pattern)
        )

    events = db.execute(
        query.order_by(Event.timestamp.asc(), Event.id.asc())
        .limit(limit)
        .offset(offset)
    ).scalars().all()

    return [EventResponse.model_validate(e) for e in events]


@router.get("/{case_id}/count")
@router.get("/cases/{case_id}/timeline/count")
def get_case_timeline_count(
    case_id: str,
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    host: str | None = Query(default=None),
    ip: str | None = Query(default=None),
    user: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get total event count for a case with optional filters."""
    case = get_authorized_case(
        case_id=case_id,
        current_user=current_user,
        db=db,
        allow_viewer=True,
    )

    query = select(Event).where(Event.case_id == case.id)

    if start_time is not None:
        query = query.where(Event.timestamp >= start_time)

    if end_time is not None:
        query = query.where(Event.timestamp <= end_time)

    if host:
        pattern = f"%{host}%"
        query = query.where(
            or_(
                Event.source.ilike(pattern),
                Event.details["host"].astext.ilike(pattern),
                Event.details["computer"].astext.ilike(pattern),
            )
        )

    if ip:
        pattern = f"%{ip}%"
        query = query.where(
            or_(
                Event.details["source_ip"].astext.ilike(pattern),
                Event.details["ip"].astext.ilike(pattern),
            )
        )

    if user:
        pattern = f"%{user}%"
        query = query.where(
            or_(
                Event.details["username"].astext.ilike(pattern),
                Event.details["user"].astext.ilike(pattern),
            )
        )

    if severity:
        pattern = f"%{severity}%"
        query = query.where(
            Event.details["severity"].astext.ilike(pattern)
        )

    total_count = db.execute(
        select(func.count()).select_from(query.subquery())
    ).scalar() or 0

    return {"total": total_count}


@router.get(
    "/{case_id}/export",
    responses={
        200: {
            "description": "Download the filtered timeline as CSV or JSON.",
            "content": {
                "application/octet-stream": {
                    "schema": {
                        "type": "string",
                        "format": "binary",
                    }
                }
            },
        }
    },
)
@router.get(
    "/cases/{case_id}/timeline/export",
    responses={
        200: {
            "description": "Download the filtered timeline as CSV or JSON.",
            "content": {
                "application/octet-stream": {
                    "schema": {
                        "type": "string",
                        "format": "binary",
                    }
                }
            },
        }
    },
)
def export_case_timeline(
    case_id: str,
    format: Literal["csv", "json"] = Query(default="json"),
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    host: str | None = Query(default=None),
    ip: str | None = Query(default=None),
    user: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    case = get_authorized_case(
        case_id=case_id,
        current_user=current_user,
        db=db,
        allow_viewer=True,
    )

    query = select(Event).where(Event.case_id == case.id)

    if start_time is not None:
        query = query.where(Event.timestamp >= start_time)

    if end_time is not None:
        query = query.where(Event.timestamp <= end_time)

    if host:
        pattern = f"%{host}%"
        query = query.where(
            or_(
                Event.source.ilike(pattern),
                Event.details["host"].astext.ilike(pattern),
                Event.details["computer"].astext.ilike(pattern),
            )
        )

    if ip:
        pattern = f"%{ip}%"
        query = query.where(
            or_(
                Event.details["source_ip"].astext.ilike(pattern),
                Event.details["ip"].astext.ilike(pattern),
            )
        )

    if user:
        pattern = f"%{user}%"
        query = query.where(
            or_(
                Event.details["username"].astext.ilike(pattern),
                Event.details["user"].astext.ilike(pattern),
            )
        )

    if severity:
        pattern = f"%{severity}%"
        query = query.where(
            Event.details["severity"].astext.ilike(pattern)
        )

    events = db.execute(
        query.order_by(Event.timestamp.asc(), Event.id.asc())
    ).scalars().all()

    filename_base = f"timeline_{case.name.replace(' ', '_').lower()}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

    if format == "csv":
        output = io.StringIO()
        fieldnames = [
            "id",
            "timestamp",
            "event_type",
            "source",
            "host",
            "user",
            "source_ip",
            "severity",
            "details",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for ev in events:
            details = ev.details or {}
            writer.writerow({
                "id": str(ev.id),
                "timestamp": ev.timestamp.isoformat(),
                "event_type": ev.event_type,
                "source": ev.source,
                "host": details.get("host") or details.get("computer") or "",
                "user": details.get("user") or details.get("username") or "",
                "source_ip": details.get("source_ip") or details.get("ip") or "",
                "severity": details.get("severity") or "",
                "details": json.dumps(details),
            })

        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{filename_base}.csv"'
            },
        )

    data = [
        {
            "id": str(ev.id),
            "timestamp": ev.timestamp.isoformat(),
            "event_type": ev.event_type,
            "source": ev.source,
            "details": ev.details,
        }
        for ev in events
    ]

    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename_base}.json"'
        },
    )
