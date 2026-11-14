DCSRE sample evidence bundle
===========================

Files:
- sample_auth.auth          Text authentication-log sample
- sample_events.csv         Structured CSV events
- sample_events.log         ISO-timestamped text log lines
- sample_traffic.pcap       Minimal classic PCAP with synthetic UDP packets
- sample_traffic.pcapng     Minimal PCAPNG with the same synthetic packets
- sample_windows_events.xml Readable Windows-event XML example (not EVTX)
- HOW_TO_CREATE_REAL_EVTX.txt Instructions to export a genuine Windows .evtx

Expected CSV records: 3
Expected log records: 3 only if your .log parser extracts these key/value lines.
The .auth file is plain text; parser support depends on your parser registry.
PCAP/PCAPNG parsing depends on an installed and registered packet-capture parser.
EVTX parsing requires an actual EVTX parser; a generic text/JSON parser cannot parse it.

If GET /api/v1/events/ returns 200 [] after uploading a .log file, HTTP 200 means
the request completed, but the empty array means no events matched that case.
Check the evidence parsing_status/parsing_error and the parser registry. A parser
might not support .log, or it may return records that the normalizer drops because
it cannot recognize timestamps. The supplied log uses ISO-8601 timestamps.
