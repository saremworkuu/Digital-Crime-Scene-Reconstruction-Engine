
# Tests for the generic CSV and JSON parser

import json
import tempfile
from pathlib import Path

from app.parsers.generic_csv_json import GenericCSVJSONParser


parser = GenericCSVJSONParser()

with tempfile.TemporaryDirectory() as temp_dir:
    folder = Path(temp_dir)

    # Test CSV parsing
    csv_file = folder / "sample.csv"
    csv_file.write_text(
        "timestamp,event\n2026-10-14,login\n2026-10-15,logout\n",
        encoding="utf-8",
    )

    csv_records = parser.parse(csv_file)

    assert len(csv_records) == 2
    assert csv_records[0]["event"] == "login"
    print("CSV test passed!")

    # Test JSON parsing
    json_file = folder / "sample.json"
    json_file.write_text(
        json.dumps([
            {"timestamp": "2026-10-14", "event": "login"},
            {"timestamp": "2026-10-15", "event": "logout"},
        ]),
        encoding="utf-8",
    )

    json_records = parser.parse(json_file)

    assert len(json_records) == 2
    assert json_records[1]["event"] == "logout"
    print("JSON test passed!")

    # Test unsupported file extension
    unsupported_file = folder / "sample.exe"
    unsupported_file.write_text("not supported", encoding="utf-8")

    try:
        parser.parse(unsupported_file)
        raise AssertionError("Unsupported files should be rejected.")
    except ValueError:
        print("Unsupported extension test passed!")

    # Test invalid JSON
    invalid_json_file = folder / "invalid.json"
    invalid_json_file.write_text("{invalid json}", encoding="utf-8")

    try:
        parser.parse(invalid_json_file)
        raise AssertionError("Invalid JSON should be rejected.")
    except json.JSONDecodeError:
        print("Invalid JSON test passed!")

print("All CSV/JSON parser tests passed!")
