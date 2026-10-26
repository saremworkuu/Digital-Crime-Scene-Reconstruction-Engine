# Tests for the Windows EVTX parser
import os
from pathlib import Path
from Evtx.Evtx import Evtx

from app.parsers.windows_evtx import WindowsEVTXParser


def test_windows_evtx_parser():
    parser = WindowsEVTXParser()

    # Set EVTX_SAMPLE to the path of a real EVTX sample file
    sample_path = os.environ.get("EVTX_SAMPLE")

    if not sample_path:
        candidate = Path(__file__).resolve().parent.parent.parent / "qa_samples" / "01_ransomware_cryptoveil" / "01_security_multihost.evtx"
        if candidate.exists():
            sample_path = str(candidate)
        else:
            raise RuntimeError(
                "Set EVTX_SAMPLE to the path of a valid .evtx sample file."
            )

    evtx_file = Path(sample_path)

    with Evtx(str(evtx_file)) as log:
        count = 0
        for event in log.records():
            count += 1
            if count == 3:
                break

    records = parser.parse(evtx_file)

    assert isinstance(records, list)
    assert len(records) > 0, "The sample should contain at least one event."
    first_record = records[0]

    assert first_record["event_type"] == "windows_event"
    assert first_record["source"] == "windows_evtx"
    assert isinstance(first_record["record_number"], int)
    assert first_record["xml"], "Each event should include its XML."
