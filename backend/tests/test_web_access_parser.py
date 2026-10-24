# Tests for the web server access log parser
import tempfile
from pathlib import Path

from app.parsers.web_access import WebAccessParser


def test_web_access_parser():
    parser = WebAccessParser()

    with tempfile.TemporaryDirectory() as temp_dir:
        folder = Path(temp_dir)
        web_file = folder / "access.log"

        web_file.write_text(
            '192.168.1.10 - - [15/Oct/2026:10:30:00 +0000] '
            '"GET /login HTTP/1.1" 401 512\n'
            '192.168.1.20 - - [15/Oct/2026:10:31:00 +0000] '
            '"POST /login HTTP/1.1" 200 128\n',
            encoding="utf-8",
        )

        records = parser.parse(web_file)

        assert len(records) == 2

        # Check the first request
        assert records[0]["source_ip"] == "192.168.1.10"
        assert records[0]["method"] == "GET"
        assert records[0]["path"] == "/login"
        assert records[0]["status_code"] == 401
        assert records[0]["response_size"] == 512
        assert records[0]["event_type"] == "web_access"

        # Check the second request
        assert records[1]["source_ip"] == "192.168.1.20"
        assert records[1]["method"] == "POST"
        assert records[1]["status_code"] == 200
        assert records[1]["response_size"] == 128
