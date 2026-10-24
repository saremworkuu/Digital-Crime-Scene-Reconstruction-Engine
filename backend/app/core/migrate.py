"""Lightweight SQLite schema patches for MVP (no Alembic yet)."""

from sqlalchemy import inspect, text

from app.core.database import Base, engine


def ensure_schema() -> None:
    """
    Patch or rebuild SQLite schema when older layouts are incompatible.

    Breaking change: cases.id was INTEGER; now UUID with created_by → users.id.
    """
    insp = inspect(engine)
    tables = set(insp.get_table_names())

    if "cases" not in tables:
        return

    columns = {c["name"]: c for c in insp.get_columns("cases")}
    needs_rebuild = False

    if "created_by" not in columns:
        needs_rebuild = True
    elif "severity" in columns or "incident_type" in columns or "owner" in columns:
        needs_rebuild = True
    else:
        # INTEGER PK vs UUID/CHAR storage
        id_type = str(columns.get("id", {}).get("type", "")).upper()
        if "INT" in id_type and "UUID" not in id_type and "CHAR" not in id_type:
            needs_rebuild = True

    if "users" not in tables:
        needs_rebuild = True

    if not needs_rebuild:
        return

    with engine.begin() as conn:
        # Drop dependent tables first (SQLite FK optional; be explicit)
        for name in (
            "audit_logs",
            "technique_hits",
            "response_tasks",
            "iocs",
            "timeline_events",
            "case_notes",
            "cases",
            "users",
        ):
            conn.execute(text(f"DROP TABLE IF EXISTS {name}"))

    Base.metadata.create_all(bind=engine)
