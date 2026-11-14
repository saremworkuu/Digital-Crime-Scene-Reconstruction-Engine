from pathlib import Path
from app.parsers.registry import get_parser
from app.parsers.generic_csv_json import GenericCSVJSONParser
from app.parsers.auth_log import AuthLogParser
from app.parsers.web_access import WebAccessParser
from app.parsers.pcap import PCAPParser
from app.parsers.windows_evtx import WindowsEVTXParser


def test_parser_registry():
    assert isinstance(get_parser(Path("events.csv")), GenericCSVJSONParser)
    assert isinstance(get_parser(Path("events.json")), GenericCSVJSONParser)
    assert isinstance(get_parser(Path("auth.auth")), AuthLogParser)
    assert isinstance(get_parser(Path("access.access")), WebAccessParser)
    assert isinstance(get_parser(Path("capture.pcap")), PCAPParser)
    assert isinstance(get_parser(Path("capture.pcapng")), PCAPParser)
    assert isinstance(get_parser(Path("system.evtx")), WindowsEVTXParser)
    assert get_parser(Path("unknown.xyz")) is None
