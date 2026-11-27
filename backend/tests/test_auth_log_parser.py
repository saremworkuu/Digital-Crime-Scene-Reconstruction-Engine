
import tempfile
from pathlib import Path

from app.parsers.auth_log import AuthLogParser


def test_auth_log_parser():
    sample_log = """\
Oct 14 08:30:00 server sshd[1234]: Failed password for alice from 192.168.1.20 port 50221 ssh2
Oct 14 08:31:00 server sshd[1235]: Accepted password for bob from 192.168.1.10 port 50222 ssh2
Oct 14 08:32:00 server sshd[1236]: Invalid user guest from 192.168.1.30
"""

    with tempfile.TemporaryDirectory() as temp_dir:
        log_file = Path(temp_dir) / "auth.log"
        log_file.write_text(sample_log, encoding="utf-8")

        parser = AuthLogParser()
        records = parser.parse(log_file)

        print("Parsed records:", records)

        assert len(records) == 3
        assert records[0]["event_type"] == "ssh_failed"
        assert records[0]["user"] == "alice"
        assert records[0]["source_ip"] == "192.168.1.20"

        assert records[1]["event_type"] == "ssh_success"
        assert records[1]["user"] == "bob"

        assert records[2]["event_type"] == "invalid_user"
        assert records[2]["user"] == "guest"

    print("All authentication log tests passed!")


if __name__ == "__main__":
    test_auth_log_parser()
