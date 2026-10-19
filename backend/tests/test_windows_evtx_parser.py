
# Tests for the Windows EVTX parser

import os
import tempfile
from pathlib import Path
from Evtx.Evtx import Evtx

from app.parsers.windows_evtx import WindowsEVTXParser


parser = WindowsEVTXParser()

# Set EVTX_SAMPLE to the path of a real EVTX sample file
sample_path = os.environ.get("EVTX_SAMPLE")

if not sample_path:
    raise RuntimeError(
        "Set EVTX_SAMPLE to the path of a valid .evtx sample file."
    )

evtx_file = Path(sample_path)


with Evtx(str(evtx_file)) as log:
    count = 0

    for event in log.records():
        print("Found record:", event)
        print("XML preview:", event.xml()[:300])
        count += 1

        if count == 3:
            break

    # print("Events found in sample:", count)


records = parser.parse(evtx_file)
print("Records extracted by our parser:", len(records))

print("EVTX file:", evtx_file)
print("File size:", evtx_file.stat().st_size, "bytes")
print("Records extracted:", len(records))
print("First records:", records[:3])

assert isinstance(records, list)
assert len(records) > 0, "The sample should contain at least one event."
first_record = records[0]

assert first_record["event_type"] == "windows_event"
assert first_record["source"] == "windows_evtx"
assert isinstance(first_record["record_number"], int)
assert first_record["xml"], "Each event should include its XML."

print(f"EVTX parser tests passed! Extracted {len(records)} records.")
