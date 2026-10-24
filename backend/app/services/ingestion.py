import csv
import json
from pathlib import Path


def analyze_file(path: Path) -> dict:
    """Basic analysis for sample purposes. Supports CSV, JSON, and text files."""
    meta = {"filename": path.name, "size": path.stat().st_size}

    if path.suffix.lower() in (".csv",):
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                reader = csv.reader(fh)
                rows = list(reader)
            meta.update({"type": "csv", "rows": len(rows), "columns": len(rows[0]) if rows else 0})
        except Exception as e:
            meta.update({"error": str(e)})
    elif path.suffix.lower() in (".json",):
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                obj = json.load(fh)
            if isinstance(obj, list):
                meta.update({"type": "json_list", "items": len(obj)})
            elif isinstance(obj, dict):
                meta.update({"type": "json_object", "keys": len(obj)})
            else:
                meta.update({"type": "json", "kind": str(type(obj))})
        except Exception as e:
            meta.update({"error": str(e)})
    else:
        # treat as text
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
            meta.update({"type": "text", "lines": len(lines)})
        except Exception as e:
            meta.update({"error": str(e)})

    return meta
# Ingestion service
