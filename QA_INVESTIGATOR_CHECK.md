# Investigator-page QA — case `1f709031-2230-42e5-965b-53bf6f51e498`

## Scope and method

Used only the selected case and its existing evidence. The configured PostgreSQL service was unavailable, so the application selected its existing local database, `backend/dcsre.db`. All 8 evidence paths were read without modifying them. SHA-256 and byte counts were calculated from raw files; event totals and timestamps were checked against the raw formats and stored normalized events. No evidence was uploaded, changed, or deleted. No report history, case, upload, audit, hash, or legal-hold implementation was changed. No branch, commit, push, stash, or reset was performed.

The user requested both raw-source QA and fixes. Backend detections were recomputed using the existing deterministic detector endpoint/service so stale findings could be compared with the current evidence. This updates the derived finding rows in the local DB only; raw evidence is unchanged. The report compiler was run in memory to inspect current output and did not save a new history version.

## Raw evidence expected values

All timestamps below are UTC where the raw source carries timezone/UTC information. `07_mailgw.log` has syslog timestamps with no year or timezone; its normalized date/time is an assumption and is called out in the UI/report limitations. Counts are format records (EVTX records, XML Event elements, packets, CSV data rows, JSON array items, or text lines), not normalized-event counts. The README is a document and correctly produces zero normalized events.

| Raw file | Bytes | SHA-256 | Raw records | First – last source time | Hosts / users / IPs observed |
|---|---:|---|---:|---|---|
| `01_security_multihost.evtx` | 69,632 | `866910108432a8eef8d07f2835272f793965b06f5e9c8db0a7dc1fc2f4bc7cce` | 31 | 2026-09-03 07:12:08 – 10:40:02 UTC | Hosts: DC-01, SRV-BKP-01, SRV-FS-02, WS-ACC-03, WS-HR-12. Users: admin_svc, mlee, SYSTEM, LocalSystem. Source IP: 10.20.1.12. |
| `02_sysmon_events.xml` | 5,972 | `40a2785e02bd46b616fb5e4a0817f3e78fe3a99a849f24b325be712f3caef615` | 14 | 2026-09-03 07:41:27 – 10:12:36 UTC | Hosts: SRV-FS-02, WS-HR-12. User: ACME\mlee. Addresses include 10.20.1.12, 10.20.2.2, 10.20.2.5 and the three TEST-NET addresses below. |
| `03_network_capture.pcap` | 30,384 | `e9dc024dce717319f59c370f1aff65f3fcf47b49306c65a7f5a2fa7e76be30cf` | 171 packets | 2026-09-03 07:41:30 – 09:30:05.285 UTC | Internal: 10.20.1.12, 10.20.2.2, 10.20.2.5, 10.20.2.8. External observed: 192.0.2.88, 198.51.100.66, 203.0.113.99. DNS names: `cdn-sync.updates-portal.example`, `files-share-drop.example`. |
| `04_netflow_export.csv` | 3,409 | `df3decf03eec0598701f41a375da30319149b1410f43db20c4fcfc12d0512f54` | 43 data rows | 2026-09-03 07:02:25 – 10:14:50 UTC | Internal: 10.20.1.12, 10.20.1.33, 10.20.2.2, 10.20.2.5, 10.20.2.8, 10.20.2.20, 10.20.2.30. External observed: 192.0.2.88, 198.51.100.66, 203.0.113.99. |
| `05_edr_alerts.json` | 2,701 | `fa6d911681f89d01893b964dbf8ec4883465960126516ffcdf271d3deb166e43` | 10 JSON items | 2026-09-03 07:41:27 – 10:40:02 UTC | Hosts: DC-01, SRV-FS-02, WS-HR-12. Users: ACME\admin_svc, ACME\mlee. |
| `06_fileserver_audit.log` | 48,444 | `d5cbe34f7cb2dbc3b547c94c620fc3494b465c12a54f90c422438c53e82d93b5` | 304 lines/records | 2026-09-03 08:00:46 – 10:37:32 UTC | Host: SRV-FS-02 (encoded in timestamped raw lines). Users: ACME\admin_svc, ACME\jsmith, ACME\kpatel, ACME\mlee. |
| `07_mailgw.log` | 604 | `930c80454ede60a36e1159fcb67f84354e32c909e08b5fd1151031fa76fa8fbc` | 3 lines | Raw syslog: Sep 3 02:14:10 – 05:02:12; no year/timezone | Host: mailgw. Recipient: mlee@acme.example. No IP address in these lines. |
| `08_README_RESTORE_FILES.txt` | 545 | `54a61a3dfb304aa238b437bc99df79a4397a08c8b65df3b888a46ff1fd8013b9` | 14 document lines | No event timestamps | Ransomware note/document, not a host or event source. |

Expected normalized-event count: **576** (31 + 14 + 171 + 43 + 10 + 304 + 3; README contributes 0). Stored case event count is 576. Raw SHA-256 and byte sizes matched all 8 evidence metadata rows.

### Suspicious behavior visible in the raw sources

- Encoded PowerShell command: `02_sysmon_events.xml`, line 12.
- LSASS access and dump path: `02_sysmon_events.xml`, lines 104 and 117; corroborating EDR alert in `05_edr_alerts.json`.
- `rclone` execution: `02_sysmon_events.xml`, line 156; outbound transfer in `04_netflow_export.csv`, record 37, to 203.0.113.99 with 4,509,715,660 `bytes_out` as recorded in that source row.
- Failed logons: `01_security_multihost.evtx`, event records 10–12 (three 4625 events, user admin_svc, source 10.20.1.12), followed by record 13 (4624). This supports the failed-then-successful sequence; it is not SSH evidence.
- Mass rename behavior: `06_fileserver_audit.log`, first matching record at line 16, with 288 matching rename records overall; EDR alert is also in `05_edr_alerts.json`.
- Shadow-copy deletion and security log clearing: represented in `05_edr_alerts.json` and corroborating Windows/Sysmon events.
- Network capture includes the three external TEST-NET IPs and the two observed DNS names listed above. Their appearance is evidence of observation only; attribution is not established by the raw file alone.
- No SSH/auth.log evidence exists among this case’s 8 current evidence files. The 10.20.1.12 address is private and appears as a Windows logon source, not an external SSH source.
- No raw evidence for SQL injection, new-user creation, or a reverse shell was identified in these 8 files. Netflow shows a large transfer; it does not by itself prove exfiltration intent.

## Page checks

`RAN` means the service/data check, test, or build was actually executed. `CODE ONLY` means the page behavior was inspected or changed in code but not exercised in a running browser. PASS is used only for RAN checks.

| Page | Check | Expected | Before | Fix | After | Execution | Result |
|---|---|---|---|---|---|---|---|
| Evidence | Case inventory count, sizes, hashes, and per-file event counts | 8 files; raw hashes/sizes as above; total 576 normalized events | Stored metadata matches raw files; no mismatch | None needed | Direct DB/raw comparison: 8 files and 576 event links; all hashes/sizes match | RAN | PASS |
| Timeline | Complete selected-case event set and source host/time | 576 events; file-server records show SRV-FS-02; no invented host | 576 stored rows, but file-server rows surfaced as `unknown_host` and browser fallback could invent SRV-FILE-01 | Parse ISO-timestamped host in EventResponse; use `unknown_host` only when no host can be recovered; annotate unzoned source times | Parser unit test confirms SRV-FS-02/mailgw extraction and timezone flag; stored event set is 576; endpoint limit is configured at 10,000. Browser rendering not exercised | RAN (parser/API) + CODE ONLY (browser) | PASS (parser/API) |
| Correlation graph | One node for each hostname/account/address; merge address aliases only when evidence links them | Hostname/IP aliases merged; unique user nodes; external addresses separate; no overlaps | Browser-built graph generated duplicate IP/host nodes, duplicate bare/domain users, and treated any attack-path IP as adversary | Use backend graph service; map internal source IP to uniquely observed workstation/host; normalize bare users only when one domain is observed; mark address nodes as `ip` | Backend graph run: 17 nodes, 25 edges; 5 named host nodes, 4 account nodes, 3 external IP nodes, 5 remaining internal IP nodes; no duplicate IDs/labels for aliases | RAN (service) + CODE ONLY (browser) | PASS (service) |
| Attack Path | Findings have linked evidence and are in event-time order | All valid findings with matched event IDs; ascending first event time | UI ordered by tactic, not event chronology; empty/unlinked records could appear | Sort by finding event timestamp and filter findings without matched event IDs | Backend recompute produced 16 linked findings; browser ordering is code-only; build succeeds | CODE ONLY | — |
| Findings | No stale SSH finding; correct matching-event times and case links | No SSH claim without SSH evidence; each detection links only selected-case events; time from first linked event | Stale SSH row referenced IDs outside this case; failed Windows 4625 sequence could be confused with SSH | Detection refresh prunes stale rows; merge canonical same-behavior findings while preserving linked events and alternate techniques; response time derives from earliest linked event | Rerun yielded 16 findings, no SSH result, 0 foreign/missing event links. 4625 records 10–12 precede successful 4624 record 13; first time 08:33:01Z | RAN | PASS |
| Reports | Current compiled report scope, times, counts, and content hash | 8 evidence files; all 5 hosts; 2 observed accounts; only external IPs in adversary-address list; matching event times; own report hash | Saved v1.0/v1.1 are historical snapshots (15 findings, 9/10 timeline rows, ingestion-time SSH row) | Report compiler consumes canonical event fields; raw-text host/user extraction used for report events; domains remain indicators and are not adversary addresses | In-memory compile: 8 evidence entries, all raw hashes rechecked as match, 97 timeline rows, 16 time-linked coverage rows, 3.0-hour dwell excluding unzoned mail time, 5 hosts, 2 users (`ACME\admin_svc`, `ACME\mlee`), external IPs 192.0.2.88/198.51.100.66/203.0.113.99, prospective version 1.2 content hash `8d58f75546ec7c0cfc4e14f841cf34dd33dba18d8af0da6187be5a61a2b59bc6`. Saved history left unchanged | RAN (compiler) + CODE ONLY (page) | PASS (compiler); historical page remains stale |
| Audit Trail | Upload and report actions render with correct actor/action | Existing case upload audit rows render; report actions are present if recorded | Audit response fields are mapped as username/resource fields that the API does not return; stored actions are lowercase; no report action rows exist | Not changed per explicit no-audit-log rule | DB read confirms 9 uploads plus case-created entries and no report action entries; browser rendering not exercised | RAN (DB read) + CODE ONLY (page) | FAIL |
| Whole site | Case isolation, counts, browser errors, dependent pages | 576 events and no cross-case data or console/network errors | Not verified in a running browser | Updated graph and dashboard data sources; removed sample dashboard figures and fictional threat locations | Backend direct checks and frontend production build pass; no running browser/API session was used to exercise each page or inspect console errors | CODE ONLY | — |

## What was missed or invented

- The old SSH finding was stale and not supported by the current evidence inventory. Three actual 4625 failures and following 4624 success are Windows events, not SSH.
- The client graph could duplicate IPs as host and IP nodes and duplicate `mlee`/`ACME\mlee`; address-role inference could imply adversary status from an attack flag alone.
- Timestamped file-server records had a known host in raw text, but the event schema did not extract it. The previous frontend fallback could assign the invented host `SRV-FILE-01`.
- The dashboard contained sample incident/compliance/remediation metrics and a fictional global map with hard-coded city counts and “real-time telemetry” copy. Those are replaced with selected-case counts and observed addresses.
- The initial report builder did not extract host/user from timestamped raw lines, which hid SRV-BKP-01 and WS-ACC-03 from some compiled report outputs. The canonical EventResponse parser is now used by report compilation.
- A source domain was included as adversary infrastructure despite the requested address-only list. The report now keeps domains as observed indicators and restricts adversary infrastructure addresses to IPs.
- A large outbound transfer is evidence of volume, not proof of exfiltration intent. Keep the finding qualified as a potential transfer anomaly pending examiner review.

## Still failing / hand checks

1. The saved v1.0/v1.1 report-history rows are immutable old snapshots and therefore still show their old counts/times until an examiner uses **Generate New Version**. I did not alter report-history data or create a new saved version.
2. Audit Trail display/action logging remains incorrect/incomplete (field mapping and no report-action entries). Audit code was explicitly out of scope.
3. The mail gateway syslog timestamp has no year or timezone in the raw file. The UI and generated report now mark its timezone as unspecified and exclude it from dwell-time calculation, but an examiner must determine the correct timezone/year from authoritative source context before relying on its position in the timeline.
4. Browser-level checks for all investigator pages, graph layout overlap, and console/network errors remain unrun. The build and backend/service checks do not establish visual browser behavior.
5. The large Netflow transfer and DNS/IP correlations require examiner interpretation. The volume is recorded; exfiltration intent, C2 attribution, and whether the delivered `.docm` content was malicious or executed are not independently established by these files.

By hand: open the selected case and check Evidence, Timeline, Correlation Graph, Attack Path, Findings, Reports, and Audit Trail. Confirm all 576 events are reachable through timeline pagination; inspect graph layout at normal window size; after review, generate a new report version if the current report page should reflect the corrected findings; verify the unzoned mail timestamp from the source system; review the large transfer and DNS/IP correlations before attributing them.

## Tests and build

- Backend: `python -m compileall -q app` — RAN, passed.
- Backend: `python -m pytest -q tests` — RAN, 61 passed, 4 pre-existing deprecation warnings.
- Frontend: `npm run build` — RAN, passed. Vite emitted existing config-loader and large-chunk warnings.
- No dependencies were installed.

## Git status at completion

Branch remains `main`. No commit was created. Working-tree changes:

| File | Why it changed |
|---|---|
| `backend/app/api/v1/detections.py` | Coalesce canonical same-behavior findings across sources and preserve linked events and alternate techniques. |
| `backend/app/api/v1/reports.py` | Feed report compilation the canonical extracted host, user, action, and IP fields. |
| `backend/app/schemas/events.py` | Extract timestamped text-log host/user values and flag timestamps without source timezone. |
| `backend/app/services/graph.py` | Resolve IP/host aliases from evidence and unify uniquely domain-qualified accounts. |
| `backend/app/services/report_fixes.py` | Use qualified summary language and a canonical label for the aggregate transfer observation. |
| `backend/app/schemas/detection.py` | Preserve multiple ATT&CK technique IDs on merged findings. |
| `backend/app/services/report.py` | Keep domains as indicators, qualify email evidence, and avoid claiming UTC for unzoned source time. |
| `backend/tests/test_detection.py` | Cover host/time parsing, graph alias merging, and address-only adversary reporting. |
| `frontend/src/components/EventTable.tsx` | Mark source timestamps without timezone in event rows. |
| `frontend/src/components/ThreatMap.tsx` | Replace fabricated geographic telemetry with selected-case observed IP addresses. |
| `frontend/src/components/TimelineView.tsx` | Mark source timestamps without timezone in timeline cards. |
| `frontend/src/pages/AttackPath.tsx` | Sort findings by event time, include all mapped technique IDs, and exclude findings without linked events. |
| `frontend/src/pages/AttackGraph.tsx` | Include all backend-classified external IPs in the address summary. |
| `frontend/src/pages/Dashboard.tsx` | Replace sample metrics with active-case counts. |
| `frontend/src/store/index.tsx` | Use backend graph, parse raw-text hosts, and remove fabricated host fallback. |
| `frontend/src/types/graph.ts` | Represent backend graph role and user identity fields. |
| `frontend/src/types/index.ts` | Carry timestamp certainty and merged ATT&CK technique IDs into investigator views. |
| `QA_INVESTIGATOR_CHECK.md` | Record raw expectations, checks, results, limitations, and changed files. |
