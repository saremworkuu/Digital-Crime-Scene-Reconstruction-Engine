import uuid
from datetime import datetime

import csv
import io
import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy import select, or_
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.db.models.case import Case
from app.db.models.events import Event
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.events import EventResponse

router = APIRouter()


@router.get("/{case_id}", response_model=list[EventResponse])
def get_case_timeline(
    case_id: uuid.UUID,
    limit: int = Query(default=100, ge=1, le=500),
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
    # 1. Verify that the case exists.
    case = db.execute(
        select(Case).where(Case.id == case_id)
    ).scalar_one_or_none()

    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found.",
        )

    # 2. Verify that the user can access the case.
    if case.created_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to view this case timeline.",
        )

    # 3. Retrieve events for this case.
    query = select(Event).where(Event.case_id == case_id)

    # 4. Apply time filters.
    if start_time is not None:
        query = query.where(Event.timestamp >= start_time)

    if end_time is not None:
        query = query.where(Event.timestamp <= end_time)

    # 5. Apply host filter.
    if host:
        pattern = f"%{host}%"
        query = query.where(
            or_(
                Event.source.ilike(pattern),
                Event.details["host"].astext.ilike(pattern),
                Event.details["computer"].astext.ilike(pattern),
            )
        )

    # 6. Apply IP filter.
    if ip:
        pattern = f"%{ip}%"
        query = query.where(
            or_(
                Event.details["source_ip"].astext.ilike(pattern),
                Event.details["ip"].astext.ilike(pattern),
            )
        )

    # 7. Apply user filter.
    if user:
        pattern = f"%{user}%"
        query = query.where(
            or_(
                Event.details["username"].astext.ilike(pattern),
                Event.details["user"].astext.ilike(pattern),
            )
        )

    # 8. Apply event severity/level filter.
    if severity:
        pattern = f"%{severity}%"
        query = query.where(
            or_(
                Event.details["severity"].astext.ilike(pattern),
                Event.details["level"].astext.ilike(pattern),
            )
        )

    # 9. Sort chronologically and paginate.
    events = db.execute(
        query
        .order_by(Event.timestamp.asc(), Event.id.asc())
        .limit(limit)
        .offset(offset)
    ).scalars().all()

    return events



@router.get("/{case_id}/export",  responses={
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
    },)
def export_case_timeline(
    case_id: uuid.UUID,
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
    # 1. Verify that the case exists.
    case = db.execute(
        select(Case).where(Case.id == case_id)
    ).scalar_one_or_none()

    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found.",
        )

    # 2. Verify that the user can access the case.
    # if case.created_by != current_user.id:
    #     raise HTTPException(
    #         status_code=status.HTTP_403_FORBIDDEN,
    #         detail="You are not authorized to export this case timeline.",
    #     )

    # 3. Start with events belonging to this case.
    query = select(Event).where(Event.case_id == case_id)

    # 4. Apply the same filters as the timeline endpoint.
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
            or_(
                Event.details["severity"].astext.ilike(pattern),
                Event.details["level"].astext.ilike(pattern),
            )
        )

    # 5. Retrieve every matching event, in chronological order.
    events = db.execute(
        query.order_by(Event.timestamp.asc(), Event.id.asc())
    ).scalars().all()

    # 6. Convert database events into the API response format.
    rows = [
        EventResponse.model_validate(event).model_dump(mode="json")
        for event in events
    ]

    filename = f"timeline_{case_id}.{format}"

    # 7. Export as JSON.
    if format == "json":
        content = json.dumps(rows, indent=2, ensure_ascii=False)

        return Response(
            content=content,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{filename}"'
                )
            },
        )

    # 8. Export as CSV.
    output = io.StringIO()

    if rows:
        fieldnames = list(dict.fromkeys(
            key for row in rows for key in row.keys()
        ))

        writer = csv.DictWriter(
            output,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )

        writer.writeheader()

        for row in rows:
            # CSV cells cannot directly store nested objects.
            csv_row = {
                key: (
                    json.dumps(value, ensure_ascii=False)
                    if isinstance(value, (dict, list))
                    else value
                )
                for key, value in row.items()
            }
            writer.writerow(csv_row)

        return Response(
        content="\ufeff" + output.getvalue(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            )
        },
    )
