# Digital Crime Scene Reconstruction Engine (DCSRE / አሻራ Ashara) — Complete Project Documentation

> This document provides an end-to-end technical reference for the **Digital Crime Scene Reconstruction Engine (DCSRE)**, codenamed **አሻራ (Ashara)**, covering its architecture, repository layout, environment configuration, database schema, security model, 8-stage forensic pipeline, complete REST API, frontend & admin console, sample datasets, testing suite, and deployment setup.

---

## Table of Contents

1. [Project Overview & Objectives](#1-project-overview--objectives)
2. [Repository & Directory Structure](#2-repository--directory-structure)
3. [Technology Stack](#3-technology-stack)
4. [Configuration & Environment Variables](#4-configuration--environment-variables)
5. [Database Architecture & Complete Schema](#5-database-architecture--complete-schema)
6. [Authentication, Security & RBAC](#6-authentication-security--rbac)
7. [8-Stage Forensic Reconstruction Pipeline](#7-8-stage-forensic-reconstruction-pipeline)
8. [Supported Evidence Formats & Parsers](#8-supported-evidence-formats--parsers)
9. [Detection Engine & Sigma Rules](#9-detection-engine--sigma-rules)
10. [Complete Backend REST API Reference](#10-complete-backend-rest-api-reference)
11. [Frontend Architecture & Pages](#11-frontend-architecture--pages)
12. [Admin Console (`/admin`)](#12-admin-console-admin)
13. [Testing & Sample Datasets](#13-testing--sample-datasets)
14. [Running, Building & Deploying](#14-running-building--deploying)

---

## 1. Project Overview & Objectives

**DCSRE (Ashara)** is a full-stack **Digital Forensics and Incident Response (DFIR)** platform built to ingest heterogeneous raw security artifacts, preserve cryptographic chain-of-custody, normalize multi-source logs into a canonical schema, run deterministic MITRE ATT&CK threat detections, reconstruct interactive attack graphs and timelines, and export self-verifying forensic reports.

### Core Design Principles
- **Cryptographic Chain of Custody**: Uploaded evidence files are streamed in 1 MB chunks, hashed with **SHA-256** upon ingestion, optionally verified against an investigator-supplied `expected_sha256`, and permanently tracked in `evidence` and `audit_log`.
- **Strict Determinism**: Findings, entity classifications, and attack paths are derived deterministically from rule evaluations and parsed event records—not probabilistic guessing.
- **Role-Based Access Control (RBAC)**: Strict separation between **System Administrators (`admin`)** and **Forensic Investigators (`investigator`)**, with JWT revocation tracking, login attempt monitoring, and comprehensive audit logging.
- **Courtroom-Ready & Tamper-Evident Reporting**: Reports default to `DRAFT` status until reviewed, compute a content-derived SHA-256 seal (`report_hash`), support version history, and export to standalone **HTML**, **PDF** (via ReportLab), and **JSON**.

---

## 2. Repository & Directory Structure

```text
Digital-Crime-Scene-Reconstruction-Engine/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                     # Node 20 CI build for frontend (`cd frontend && npm run build`)
│   │   └── security.yml               # Trivy filesystem vulnerability scanner (CRITICAL, HIGH)
│   ├── CODEOWNERS
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── ISSUE_TEMPLATE/
├── backend/                           # FastAPI + SQLAlchemy + Forensic Pipeline Backend
│   ├── .env                           # Active backend environment configuration
│   ├── alembic.ini                    # Alembic database migration configuration
│   ├── Dockerfile                     # Python 3.11-slim container running uvicorn on :8000
│   ├── requirements.txt               # Core Python dependencies
│   ├── app/
│   │   ├── main.py                    # FastAPI app entrypoint, CORS, rate limiter, startup seeding, /health
│   │   ├── core/                      # Config, JWT/Argon2 security, RBAC permissions, auth dependencies, rate limit
│   │   ├── db/                        # Engine/session (PostgreSQL + SQLite fallback), init_db, seed_admin_data
│   │   │   ├── models/                # SQLAlchemy ORM models (17 tables)
│   │   │   └── migrations/versions/   # 16 Alembic schema migration scripts
│   │   ├── parsers/                   # 11 modular artifact parsers + dynamic parser registry
│   │   ├── rules/                     # 10 YAML Sigma-style detection rules
│   │   ├── schemas/                   # Pydantic v2 request/response schemas
│   │   ├── services/                  # Normalizer, event batch writer, detection engines, graph, correlation, reports, audit
│   │   └── api/v1/                    # Versioned REST endpoints + /admin sub-routers
│   ├── tests/                         # conftest.py + 18 pytest unit/integration/E2E test modules
│   ├── test_evidence/                 # Synthetic forensic files (EVTX XML, PCAP, PCAPNG, auth, csv, json, txt)
│   └── uploads/evidence/              # Persistent local evidence binary storage (<uuid>.bin or case dir)
├── frontend/                          # Primary React 19 + TypeScript + Vite 8 + Tailwind v4 Frontend
│   ├── Dockerfile                     # Multi-stage Node 18 builder -> Nginx static server (:80)
│   ├── package.json                   # Frontend dependencies & scripts (dev, build, preview, lint)
│   ├── vite.config.ts                 # Vite config with /api -> backend proxy & asset sync
│   └── src/
│       ├── main.tsx / App.tsx         # App entry, MainLayout, role routing, 3D ambient backdrop
│       ├── api/                       # Typed Fetch client (`ApiClient`) and domain API wrappers
│       ├── store/                     # Global React Context (`AppProvider` / `useApp`) + modular stores
│       ├── hooks/                     # Custom React hooks (`useAuth`, `useCase`, `useUpload`, `useGraph`, etc.)
│       ├── pages/                     # Public & Investigator views (Home, Dashboard, Cases, Evidence, Timeline, etc.)
│       ├── admin/                     # Dedicated `/admin` console (AdminApp, AdminGuard, 9 management pages)
│       ├── components/                # Reusable UI, charts, 3D Three.js globes/backdrops, ErrorBoundary
│       ├── services/                  # Client-side hashing, sample parsers, correlation, admin services
│       ├── types/ & utils/            # TypeScript domain models & formatting/export utilities
│       └── mocks/admin/               # Seed/fallback structures for admin UI
├── docs/                              # High-level project docs (API.md, ARCHITECTURE.md, SCHEMA.md, SRS.md, USER_GUIDE.md)
├── qa_samples/                        # Realistic multi-file attack scenarios (ransomware, web server compromise)
├── sample-data/scenario-1/            # Quick-test scenario bundle (access.log, auth.log, capture.pcap, windows-security.evtx)
├── samples/                           # Sample JSON/CSV case and evidence payloads
├── screenshots/                       # UI reference screenshots synced from QA artifacts on startup
├── docker-compose.yml                 # 3-service stack: frontend (:3000), backend (:8000), PostgreSQL 15 (:5432)
└── README.md                          # Project summary, team info, and quick start
```

> **Note on Root `src/` & `public/`**: The repository root also retains legacy mirrored frontend files (`src/`, `public/`, `vite.config.ts`, `tsconfig.json`, `index.html`). The canonical production and CI frontend workspace is **`frontend/`**, as configured in `.github/workflows/ci.yml` and `docker-compose.yml`.

---

## 3. Technology Stack

### Backend (`backend/requirements.txt`)
| Package | Version / Role |
|---|---|
| **FastAPI** | `0.104.1` — Async/REST web framework & automatic OpenAPI (`/docs`, `/redoc`) |
| **Uvicorn** | `0.24.0` — ASGI server (`uvicorn app.main:app`) |
| **SQLAlchemy** | `2.0.23` — ORM with PostgreSQL `UUID` & `JSONB` types (+ custom SQLite `@compiles` adapters) |
| **Alembic** | `1.12.1` — Database schema version migrations |
| **PostgreSQL / psycopg2-binary** | `2.9.9` — Primary database (compatible with Neon serverless Postgres & Docker Postgres 15) |
| **Pydantic & pydantic-settings** | `2.5.0` / `2.1.0` — Schema validation & `.env` settings loading |
| **argon2-cffi** & **passlib[bcrypt]** | `25.1.0` / `1.7.4` — Primary Argon2 password hashing |
| **python-jose[cryptography]** | `3.3.0` — HS256 JWT token signing & verification |
| **slowapi** | `0.1.10` — Request rate limiting on authentication/API endpoints |
| **python-evtx** | `0.8.1` — Binary Windows `.evtx` forensic event log parser |
| **scapy** | `2.8.0` — `.pcap` / `.pcapng` packet & DNS/protocol parser |
| **reportlab** | PDF document generation for downloadable forensic investigation reports |
| **httpx** / **pytest** | Async HTTP test client & test runner |

### Frontend (`frontend/package.json`)
| Package | Version / Role |
|---|---|
| **React & React DOM** | `^19.0.1` — UI rendering (wrapped in React `StrictMode`) |
| **TypeScript** | `^7.0.2` — Static typing across stores, API responses, and components |
| **Vite & `@vitejs/plugin-react`** | `^8.3.0` / `^6.1.1` — Dev server (port `3000`) & production bundler |
| **Tailwind CSS (`@tailwindcss/vite`)** | `^4.3.3` — Utility-first styling (Charcoal `#0e0d0d` & Burnt Orange `#f95721` theme) |
| **Three.js** | `^0.186.1` — Real-time 3D interactive threat globes and ambient constellations |
| **Motion** | `^12.23.24` — Page transitions and UI animations |
| **Lucide React** | `^0.546.0` — Iconography |
| **@google/genai** | `^2.4.0` — Included in frontend dependencies |

---

## 4. Configuration & Environment Variables

### Backend Settings (`backend/app/core/config.py`)
Loaded automatically from `backend/.env` (`extra="ignore"`):

| Variable | Description | Default / Example |
|---|---|---|
| `DATABASE_URL` | SQLAlchemy database connection URI | `postgresql://...` (falls back to `sqlite:///dcsre.db` if Postgres TCP port is unreachable) |
| `SECRET_KEY` | Cryptographic secret used to sign JWTs | Long random secret string |
| `ALGORITHM` | JWT signing algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | JWT access token lifetime in minutes | `10080` (7 days default; `.env` overrides e.g. `480`) |
| `CORS_ORIGINS` | Comma-separated allowed browser origins | `https://...` (+ `localhost:3000`, `3001`, `5173` added automatically in `main.py`) |
| `MAX_UPLOADS_SIZE` | Maximum evidence upload size in bytes | `104857600` (100 MB; `evidence.py` also enforces `100 * 1024 * 1024`) |
| `UPLOAD_DIR` | Root directory for stored forensic uploads | `uploads` (evidence stored under `<UPLOAD_DIR>/evidence`) |

### Frontend Configuration (`frontend/src/api/client.ts` & `frontend/vite.config.ts`)
- **Development (`npm run dev`)**: `ApiClient` defaults `baseUrl` to `/api/v1`, and Vite proxies `/api/*` to `process.env.VITE_BACKEND_TARGET || 'http://localhost:8000'`.
- **Production (`npm run build`)**: Uses `import.meta.env.VITE_API_BASE_URL` if set, otherwise `${RENDER_BACKEND_URL}/api/v1` (`https://digital-crime-scene-reconstruction-engine.onrender.com/api/v1`).
- **Session & Navigation Storage**:
  - `localStorage`: `dcsre_access_token` (JWT Bearer token)
  - `sessionStorage`: `dcsre_current_page`, `dcsre_active_case_id`, `dcsre_error_auto_reload_at` (for crash recovery deduplication)

---

## 5. Database Architecture & Complete Schema

### Dual-Engine Resilience (`backend/app/db/session.py` & `init_db.py`)
1. On startup, `session.py` checks TCP socket reachability (`timeout=2.0s`) and runs a `1s` test connection against `DATABASE_URL`. If PostgreSQL is unavailable, it automatically falls back to a local `sqlite:///dcsre.db`.
2. Custom SQLAlchemy `@compiles(UUID, "sqlite")` and `@compiles(JSONB, "sqlite")` handlers allow PostgreSQL-native UUID and JSONB models to run transparently on SQLite.
3. Engine uses `pool_pre_ping=True` and `pool_recycle=300` for resilient pooled connections (such as Neon serverless PostgreSQL).
4. `on_startup()` in `main.py` calls `init_db()`, which executes `migrate_schema()` (idempotent `ADD COLUMN IF NOT EXISTS` checks), `Base.metadata.create_all()`, and `seed_admin_data()`.

### All Database Tables (`17` Registered Tables)

| Table | Purpose | Key Columns & Types |
|---|---|---|
| `users` | Platform accounts (admins & investigators) | `id: UUID (PK)`, `username: VARCHAR (unique)`, `email: VARCHAR (unique)`, `hashed_password: VARCHAR`, `role: Enum(admin, investigator)`, `is_active: BOOLEAN`, `department: VARCHAR`, `badge_id: VARCHAR`, `two_factor_enabled: BOOLEAN`, `status: VARCHAR(20)`, `sessions: JSONB`, `created_at`, `updated_at` |
| `cases` | Forensic investigations | `id: UUID (PK)`, `name: VARCHAR`, `description: TEXT`, `status: Enum(open, in_progress, closed)`, `created_by: UUID (FK -> users.id)`, `is_deleted: BOOLEAN`, `deleted_at: DATETIME`, `legal_hold: BOOLEAN`, `is_archived: BOOLEAN`, `created_at`, `updated_at` |
| `case_assignments` | Investigator-to-case links | `id: UUID (PK)`, `case_id: UUID (FK)`, `user_id: UUID (FK)`, `assigned_by: UUID (FK)`, `assigned_at: DATETIME` |
| `evidence` | Uploaded artifact metadata & chain of custody | `id: UUID (PK)`, `case_id: UUID (FK)`, `uploaded_by: UUID (FK)`, `filename: VARCHAR(255)`, `description: TEXT`, `file_type: VARCHAR(100)`, `file_path: VARCHAR(1024)`, `sha256_hash: VARCHAR(64)`, `expected_sha256: VARCHAR(64)`, `verified: BOOLEAN`, `file_size: INTEGER`, `parsing_status: Enum(pending, parsed, failed)`, `parser_used: VARCHAR(100)`, `parsing_error: TEXT`, `uploaded_at: DATETIME` |
| `events` | Canonical normalized forensic events | `id: UUID (PK)`, `case_id: UUID (FK)`, `evidence_id: UUID (FK)`, `timestamp: DATETIME`, `event_type: VARCHAR`, `source: VARCHAR`, `details: JSONB`, `fingerprint: VARCHAR(64)` |
| `event_evidence` | Many-to-many deduplicated event-to-evidence provenance | `event_id: UUID`, `evidence_id: UUID` |
| `detections` | Triggered security findings mapped to MITRE ATT&CK | `id: UUID (PK)`, `case_id: UUID (FK)`, `rule_id: VARCHAR`, `rule_name: VARCHAR`, `severity: Enum(low, medium, high, critical)`, `description: TEXT`, `mitre_technique: VARCHAR`, `rule_information: JSONB`, `is_false_positive: BOOLEAN`, `detected_at: DATETIME` |
| `detection_events` | Links findings to exact supporting event IDs | `detection_id: UUID`, `event_id: UUID` |
| `entities` | Extracted forensic entities (hosts, IPs, users) | `id: UUID (PK)`, `case_id: UUID (FK)`, `type: VARCHAR`, `name: VARCHAR`, `attributes: JSONB` |
| `relationships` | Graph edges between entities | `id: UUID (PK)`, `case_id: UUID (FK)`, `source_entity_id: UUID`, `target_entity_id: UUID`, `relationship_type: VARCHAR` |
| `reports` | Versioned saved forensic reports & seals | `id: UUID (PK)`, `case_id: UUID (FK)`, `title: VARCHAR`, `version: VARCHAR`, `generator_name: VARCHAR`, `content: TEXT` (HTML), `report_data: TEXT` (JSON), `generated_at: DATETIME` |
| `audit_log` | Tamper-evident chain of custody & user action log | `id: UUID (PK)`, `user_id: UUID`, `case_id: UUID`, `action: VARCHAR`, `resource: VARCHAR`, `ip_address: VARCHAR(45)`, `user_agent: TEXT`, `details: JSONB`, `timestamp: DATETIME` |
| `sigma_rules` | Admin-managed Sigma detection rules | `id: VARCHAR(64) (PK)`, `name: VARCHAR(255)`, `severity: VARCHAR(20)`, `mitre_id: VARCHAR(50)`, `enabled: BOOLEAN`, `times_triggered: INTEGER`, `description: TEXT`, `query: TEXT`, `created_at: DATETIME` |
| `contact_messages` | Public incident escalation & support inbox | `id: VARCHAR(64) (PK)`, `reference: VARCHAR(64)`, `sender_name`, `sender_email`, `sender_phone`, `subject`, `category`, `status`, `priority`, `assignee`, `date`, `is_read: BOOLEAN`, `body: TEXT`, `reply_thread: JSONB` |
| `system_settings` | Platform-wide security & retention settings | `id: VARCHAR(64) (PK)`, `time_zone`, `org_name`, `retention_days`, `min_password_length`, `two_factor_enforced`, `failed_login_lockout_limit`, `updated_at` |
| `login_attempts` | Failed login tracking for brute-force auditing | `id: UUID (PK)`, `email: VARCHAR(254)`, `ip_address: VARCHAR(45)`, `failed_at: DATETIME` |
| `revoked_tokens` | JWT logout blacklist by `jti` | `id: UUID (PK)`, `jti: VARCHAR(36)`, `expires_at: DATETIME` |

---

## 6. Authentication, Security & RBAC

- **Password Security (`backend/app/core/security.py`)**: Uses **Argon2** (`argon2.PasswordHasher`) for salted password hashing and verification.
- **JWT Tokens**: Signed using `HS256` with `sub` (User UUID), `iat`, `exp`, and a unique `jti` UUID stored in `revoked_tokens` on `/auth/logout`.
- **Registration Validation (`backend/app/api/v1/auth.py`)**: Rejects disposable email domains (`mailinator.com`, `yopmail.com`, etc.), fake/placeholder domains (`example.com`, `test.com`, etc.), and placeholder usernames (`test`, `dummy`, `asdf`, etc.).
- **Rate Limiting**: Powered by `slowapi` (`Limiter(key_func=get_remote_address)`).
- **Permissions (`backend/app/core/permissions.py`)**:
  - `require_admin`: Restricts `/api/v1/admin/*` and admin user-list endpoints to `UserRole.ADMIN`.
  - `require_investigator_or_admin`: Allows `UserRole.ADMIN` and `UserRole.INVESTIGATOR`.
  - `get_authorized_case`: Supports lookup by UUID or scenario slug/name (auto-provisioning slug-based scenario cases when needed) and enforces active case access (`is_deleted == False`) for authenticated admins and investigators.
- **Seeded Accounts (`backend/app/db/seed_admin_data.py`)**:
  - **Admin**: `saremworkuu@gmail.com` / `Admin@2026!`
  - **Investigator**: `investigator@dcsre.corp` / `Investigator#2026`
  - **Additional Seeded Team Accounts**: `m.vance@dcsre.net` (`Investigator@2026!`), `e.rostova@dcsre.net` (`Investigator@2026!`), `d.kim@dcsre.audit` (`Auditor@2026!`).

---

## 7. 8-Stage Forensic Reconstruction Pipeline

1. **Stage 1 — Evidence Ingestion & Custody (`api/v1/evidence.py`)**:
   - Validates extension against `ALLOWED_EXTENSIONS` (`.log`, `.txt`, `.evtx`, `.pcap`, `.pcapng`, `.csv`, `.json`, `.auth`, `.access`, `.audit`, `.dat`, `.bin`, `.syslog`, `.reg`, `.dump`, `.raw`, `.xml`, `.gz`, `.zip`, `.tar`).
   - Streams upload in `1 MB` chunks (max `100 MB`), computes SHA-256 incrementally, writes to `UPLOAD_DIR/evidence/`, verifies optional `expected_sha256`, and records an `AuditLog` entry.
2. **Stage 2 — Parser Dispatch (`parsers/registry.py`)**:
   - Selects the appropriate `BaseParser` implementation based on original filename & extension, returning raw dictionaries per extracted record.
3. **Stage 3 — Canonical Normalization & Deduplication (`services/normalizer.py` & `services/event_service.py`)**:
   - Normalizes heterogeneous timestamps (`first_timestamp` Unix floats, syslog `Oct 14 08:30:00`, Apache/Nginx CLF `22/Jul/2026:00:57:48 +0000`, ISO-8601) to UTC `YYYY-MM-DDTHH:MM:SSZ`.
   - Resolves `host` (with `host_inferred` tracking), `user`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `process`, `command_line`, `action`, `outcome`, and `raw`.
   - Computes deterministic SHA-256 `fingerprint` (`(source_file, source_record_id)` when available, else canonical payload tuple) and batch-inserts deduplicated `Event` + `EventEvidence` links.
4. **Stage 4 — Sigma Field Mapping (`services/detection_engine.py`)**:
   - Maps Sigma rule fields (`Image`, `CommandLine`, `ParentImage`, `User`, `EventID`, `TargetFilename`, `SourceIp`, `DestinationIp`, `DestinationPort`, `QueryName`, `Computer`, `cpu_percent`, etc.) via `SIGMA_FIELD_MAP` and evaluates modifiers (`equals`, `contains`, `startswith`, `endswith`, `re`/`regex`, `all`, glob `*`/`?`).
5. **Stage 5 — Deterministic Detection Engine (`services/detection.py` & `api/v1/detections.py`)**:
   - Runs built-in correlation & heuristic detectors plus loaded rules, coalesces overlapping findings by host scope, assigns MITRE ATT&CK tactic/technique via `TACTIC_BY_TECHNIQUE` (`report_fixes.py`), and persists `Detection` + `DetectionEvent` associations.
6. **Stage 6 — Evidence-Led Entity Classification (`services/entity_classification.py`)**:
   - Distinguishes internal networks (`is_internal_ip`: RFC1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, loopback, link-local) from external indicators.
   - Assigns infrastructure roles (`C2`, `Payload`, `Exfiltration`, `Attack Source`) strictly from confirmed finding tactics/roles rather than traffic-only guesses.
7. **Stage 7 — Correlation & Attack Graph (`services/correlation.py` & `services/graph.py`)**:
   - `correlate_attack_chains()` links chronologically ordered events sharing hosts, users, or IP addresses within a rolling time window and computes chain confidence scores.
   - `build_attack_graph()` merges IPs to hosts using evidence-derived mappings and outputs React-ready nodes and directed edges (with `attack_path_only` filtering).
8. **Stage 8 — Timeline & Forensic Reporting (`api/v1/timeline.py`, `services/report.py`, `api/v1/reports.py`)**:
   - Unified chronological event timeline with server-side filters (`start_time`, `end_time`, `host`, `ip`, `user`, `severity`) and CSV/JSON export.
   - Versioned report compiler generating executive summaries, evidence manifests, custody verification tables, MITRE-grouped attack sequences, IOC tables, methodology/limitations, and finding-cited remediation directives—sealed with `_compute_report_hash()` and exportable as HTML or ReportLab PDF.

---

## 8. Supported Evidence Formats & Parsers

Location: `backend/app/parsers/` (`BaseParser` interface in `base_parser.py`, dispatched by `get_parser()` in `registry.py`).

| Parser Module / Class | Triggered By | Extracted Telemetry |
|---|---|---|
| `auditd.py` (`AuditdParser`) | Filename contains `audit` or `.audit`/`.auditd` (checked *before* `.log`) | Groups multi-line records sharing `msg=audit(ts:serial)`, merges `SYSCALL` + `EXECVE`, reconstructs `command_line` from `a0..aN` |
| `windows_evtx.py` (`WindowsEVTXParser`) | `.evtx` (via `python-evtx`) and `.xml` (`xml.etree.ElementTree`) | Windows Security & Sysmon events (e.g., `4624`/`4625` logons, `4688`/Sysmon `1` process creation, `7045` service install, `4104` PowerShell), extracts `EventData`/`UserData`, `Computer`, `CommandLine` |
| `auth_log.py` (`AuthLogParser`) | `.auth` or `.log` containing `auth`/`secure` | SSH failed/accepted logins (`source_ip`, `source_port`, `user`), invalid users, `sudo` privilege escalation commands |
| `web_access.py` (`WebAccessParser`) | `.access` or `.log` containing `access`/`nginx`/`apache`/`web` | Apache/Nginx Combined/Common Log Format & key-value web logs (`method`, `path`, `status_code`, `response_size`, `source_ip`, user agents) |
| `pcap.py` (`PCAPParser`) & `pcapng.py` (`PCAPNGParser`) | `.pcap`, `.pcapng` (via `scapy`, falls back to `LogFileParser` if missing) | IPv4/IPv6 packet flows, TCP/UDP/ICMP ports, packet sizes, DNS queries (`QueryName`), UTC timestamps |
| `generic_csv_json.py` (`GenericCSVJSONParser`) | `.csv`, `.json` (and fallback for `.evtx`) | Tabular SIEM/NetFlow exports and JSON event arrays/objects (`edr_alerts.json`, `siem_events.json`, CSV timelines) |
| `log_parser.py` (`LogFileParser`) | Other `.log` files | Generic line-by-line timestamped syslog / server log parsing |
| `txt_parser.py` (`TextFileParser`) | `.txt` (and `.xml` fallback) | Freeform investigator notes, ransom notes, structured/semi-structured `.txt` telemetry |
| `filesystem.py` & `structured_log.py` | Auxiliary parser modules | Filesystem artifact and structured log helpers |

---

## 9. Detection Engine & Sigma Rules

### Built-in Python Detectors (`backend/app/services/detection.py` & `detection_engine.py`)
- **Initial Access & Web**: `detect_web_sql_injection`, scanner User-Agents, double-extension uploads, webshell access, `detect_macro_attachment_delivery` (`.docm`/`.xlsm`/`.pptm` & script archives, `T1566.001`).
- **Brute Force & Credential Access**: `detect_repeated_failed_logins`, `detect_failed_then_successful_login`, LSASS/credential dumping indicators.
- **Execution & Privilege Escalation**: `detect_privilege_escalation`, reverse shells (`/dev/tcp`), `sudo` escapes, `useradd`/group changes, `/tmp` download+exec, `crontab` persistence.
- **Lateral Movement**: `detect_lateral_movement`, `detect_smb_lateral_movement` (SMB ports `445`/`139`, `ADMIN$`/`IPC$`/`C$`, Windows Type `3` logons across `>= 3` distinct internal targets within `60s`, `T1021.002`).
- **C2 & Exfiltration & Impact**: `detect_periodic_beaconing` (`>= 4` periodic external connections with interval tolerance, `T1071`), `detect_dns_tunneling`, `detect_data_exfiltration` (`mysqldump`+`scp`, `rclone`), `history -c`/log clearing, cryptomining (`cpu_percent > 90%`, miner ports).

### YAML Rule Definitions (`backend/app/rules/*.yml`)
Loaded dynamically via `rule_loader.py`:
- `data_exfiltration.yml`
- `dns_tunneling.yml`
- `failed_then_successful_login.yml`
- `lateral_movement.yml`
- `mail_macro_attachment.yml` (`T1566.001` — Macro-Enabled or Script Archive Delivered)
- `periodic_c2_beaconing.yml` (`T1071` — Periodic External Beaconing)
- `privilege_escalation.yml`
- `smb_lateral_movement.yml` (`T1021.002` — SMB or Remote Logon Lateral Movement)
- `ssh_bruteforce.yml`
- `web_sql_injection.yml`

---

## 10. Complete Backend REST API Reference

Base URL: `/api/v1` (plus `GET /health`, `GET /docs`, `GET /redoc`, `GET /openapi.json`).

### Authentication & Users (`/api/v1/auth`, `/api/v1/users`)
- `POST /auth/login`, `POST /auth/signup`, `POST /auth/register`, `POST /auth/logout`, `POST /auth/refresh`, `POST /auth/change-password`
- `GET /auth/me`, `PATCH /auth/me`, `PUT /auth/me`, `GET /auth/users`
- `GET /users/`, `GET /users/me`, `PUT /users/me`, `PATCH /users/me`, `PATCH /users/{user_id}`, `PATCH /users/{user_id}/status`

### Cases (`/api/v1/cases`)
- `GET /cases`, `POST /cases` (auto-enriched with `evidence_count`, `event_count`, `detection_count`, `critical_detection_count`, `assigned_users`, `owner_name`)
- `GET /cases/{case_id}`, `PUT /cases/{case_id}`, `PATCH /cases/{case_id}`, `DELETE /cases/{case_id}` (soft delete)
- `POST /cases/{case_id}/assign`, `POST /cases/{case_id}/assignments`

### Evidence Ingestion & Vault (`/api/v1/evidence` & `/api/v1/cases/{case_id}/evidence`)
- `GET /evidence/`, `POST /evidence/`, `POST /evidence/cases/{case_id}/evidence/upload`, `POST /cases/{case_id}/evidence`, `POST /cases/{case_id}/evidence/upload`
- `GET /evidence/{evidence_id}/download`, `POST /evidence/{evidence_id}/reparse`, `DELETE /evidence/{evidence_id}`

### Events, Timeline & Attack Graph
- `GET /events/`, `GET /events/cases/{case_id}/events`, `GET /events/{event_id}`, `GET /cases/{case_id}/events`
- `GET /timeline/{case_id}`, `GET /timeline/{case_id}/count`, `GET /timeline/{case_id}/export` (plus `/cases/{case_id}/timeline` aliases)
- `GET /graph/{case_id}/graph`, `GET /graph/cases/{case_id}/graph`, `GET /cases/{case_id}/graph` (supports `?attack_path_only=true|false`)

### Detections & Rules (`/api/v1/detections`)
- `GET /detections/`, `GET /detections/cases/{case_id}/detections`, `GET /cases/{case_id}/detections`
- `POST /detections/cases/{case_id}/run`, `POST /cases/{case_id}/run`
- `GET /detections/cases/{case_id}/coverage`, `GET /detections/cases/{case_id}/detections/coverage`
- `GET /detections/{detection_id}`, `POST /detections/{detection_id}/false-positive`
- `GET /detections/rules`, `POST /detections/rules/reload`

### Reports (`/api/v1/reports` & `/api/v1/cases/{case_id}/reports`)
- `GET /reports/{case_id}/report`, `GET /reports/{case_id}/reports`
- `POST /reports/{case_id}/reports/generate` (creates & persists a new versioned report)
- `GET /reports/{case_id}/reports/html`, `GET /reports/{case_id}/reports/pdf`
- `GET /reports/{case_id}/reports/{report_id}/data`, `.../html`, `.../pdf`, `DELETE /reports/{case_id}/reports/{report_id}`

### Audit, Public Contact & Admin (`/api/v1/audit`, `/api/v1/contact`, `/api/v1/admin`)
- **Audit**: `GET /audit`, `GET /audit/logs`, `GET /audit/export`
- **Public Contact**: `POST /contact` (creates prioritized support/incident ticket `አሻራ-XXXXXX`)
- **Admin Users**: `GET/POST /admin/users`, `GET/PATCH/DELETE /admin/users/{user_id}`, `POST .../reset-password`, `POST .../sessions/{session_id}/terminate`
- **Admin Cases & Evidence**: `GET /admin/cases`, `PATCH /admin/cases/{case_id}/{status|assign|archive|legal-hold}`, `GET /admin/evidence`, `POST /admin/evidence/{id}/verify`, `DELETE /admin/evidence/{id}`
- **Admin Sigma Rules**: `GET/POST /admin/rules`, `POST /admin/rules/import`, `PATCH/DELETE /admin/rules/{rule_id}`, `PATCH .../toggle`, `POST .../test`
- **Admin Messages & Audit**: `GET /admin/messages`, `GET /admin/messages/count`, `PATCH .../{read|status|priority|assign}`, `POST .../{reply|spam}`, `DELETE`, `GET/POST /admin/audit`
- **Admin System**: `GET /admin/system/health`, `GET/PUT/PATCH /admin/system/settings`, `POST /admin/system/queue/{job_id}/retry`, `POST /admin/system/reset-demo`

---

## 11. Frontend Architecture & Pages

### State Management (`frontend/src/store/index.tsx`)
- Centralized `AppProvider` (`useApp()`), persisted across Vite HMR edits via `globalThis.__DCSRE_APP_CONTEXT__`.
- Automatically restores authenticated sessions (`dcsre_access_token`), preserves `currentPage` and `activeCaseId` in `sessionStorage`, synchronizes cases/evidence/events/detections/audit entries with the backend API, handles case creation/deletion/evidence upload workflows, and supports dark/light theme toggling.
- `ErrorBoundary.tsx` intercepts unhandled React errors and triggers an automatic workspace reload (with a 3-second `sessionStorage` reload-loop guard).

### Public & Investigator Pages (`frontend/src/pages/`)
| Page | Description |
|---|---|
| `Home.tsx`, `About.tsx`, `Contact.tsx` | Public portal with interactive 3D global cyber threat topology (`CyberGlobe3D` / `ThreatHeroGlobe`), platform overview, and incident escalation contact form |
| `Login.tsx`, `Register.tsx` | Authentication & account registration backed by `/api/v1/auth/*` |
| `Dashboard.tsx` | Investigator command center with active case telemetry, MITRE/severity summaries, compliance metrics, and quick actions |
| `Cases.tsx` & `CaseDetail.tsx` | Investigation portfolio management, creation (`NewTaskModal`), deletion, and per-case drill-down |
| `Evidence.tsx` | Drag-and-drop multi-file uploader (`UploadDropzone`), SHA-256 verification badges, re-parse trigger, download, and deletion |
| `Timeline.tsx` | High-resolution chronological event explorer (`TimelineView`, `EventTable`, `EventDetailPanel`, `RawEventModal`) |
| `AttackGraph.tsx` & `AttackPath.tsx` | Interactive 2D/3D network & host attack topology (`GraphView`, `ThreatMap`) distinguishing compromised hosts and adversary infrastructure |
| `Detections.tsx` / `Findings.tsx` | Rule findings explorer (`DetectionCard`, `MitreBadge`, `SeverityTag`), false-positive triage, and rule coverage views |
| `Reports.tsx` | Live report preview (`ReportPreview`) with version history, silent automatic backend reload/retry, and JSON / HTML / PDF export |
| `AuditLog.tsx` | Case & system audit trail viewer with filtering |

---

## 12. Admin Console (`/admin`)

Mounted in `frontend/src/admin/AdminApp.tsx`, protected by `AdminGuard.tsx`, and routed via `#/admin/<tab>`:
- **Dashboard (`DashboardPage.tsx`)**: Platform-wide KPIs across users, cases, evidence volume, rules, and alerts.
- **Users (`UsersPage.tsx`)**: Create, edit, activate/suspend users, reset passwords, and terminate active device sessions.
- **Cases (`CasesPage.tsx`)**: Case lifecycle controls—status transitions, investigator assignment, legal hold toggles, and archival.
- **Evidence (`EvidencePage.tsx`)**: Cross-case evidence custody inspection, manual integrity verification, and deletion.
- **Sigma Rules (`RulesPage.tsx`)**: Enable/disable rules, import new YAML/Sigma rules, edit queries, and test rules live.
- **Messages (`MessagesPage.tsx`)**: Manage inbound `/contact` incident escalation tickets (read, reply threads, priority, assignee, spam/delete).
- **Audit Logs (`AuditLogPage.tsx`)**: Full administrative audit inspection.
- **System Health (`SystemHealthPage.tsx`)**: Live service status & background job queue retry controls.
- **Settings (`SettingsPage.tsx`)**: Configure organization name, timezone, data retention days, password policy, 2FA enforcement, and lockout threshold.

---

## 13. Testing & Sample Datasets

### Backend Test Suite (`backend/tests/`)
18 pytest test modules (`test_*.py`) plus `conftest.py` covering parsers, services, and API E2E flows:
- **Parsers**: `test_auth_log_parser.py`, `test_pcap_parser.py`, `test_web_access_parser.py`, `test_windows_evtx_parser.py`, `test_parsers.py`, `test_registry.py`
- **Services**: `test_normalizer.py`, `test_event_service.py`, `test_correlation.py`, `test_detection.py`, `test_detection_case_isolation.py`
- **API & E2E**: `test_auth.py`, `test_cases.py`, `test_evidence_upload.py`, `test_evidence_upload_integration.py`, `test_reports.py`, `test_audit_report_events.py`, `test_full_system_e2e.py`, `test_parts_abc_fixes.py`

### Included Forensic Sample Bundles
- **`qa_samples/01_ransomware_cryptoveil/`**: Full multi-stage ransomware intrusion (`01_security_multihost.evtx`, `02_sysmon_events.xml`, `03_network_capture.pcap`, `04_netflow_export.csv`, `05_edr_alerts.json`, `06_fileserver_audit.log`, `07_mailgw.log`, `08_README_RESTORE_FILES.txt`).
- **`qa_samples/03_web_server_compromise/`**: `01_apache_access.log`.
- **`sample-data/scenario-1/`**: `access.log`, `auth.log`, `capture.pcap`, `windows-security.evtx`, `README.md`.
- **`backend/test_evidence/`**: Targeted parser fixtures (`sample_windows_events.xml`, `sample_traffic.pcap`, `sample_traffic.pcapng`, `sample_auth.auth`, `auth_server.csv`, `sample_events.csv`, `sample_events.json`, `siem_events.json`, `testing detections/`).

---

## 14. Running, Building & Deploying

### Local Backend Setup (Windows PowerShell / Linux)
```powershell
cd Digital-Crime-Scene-Reconstruction-Engine\backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install reportlab pytest

# Configure backend/.env (DATABASE_URL, SECRET_KEY, CORS_ORIGINS, UPLOAD_DIR)
.\venv\Scripts\uvicorn.exe app.main:app --reload --host 0.0.0.0 --port 8000
```
- Interactive Swagger UI: `http://localhost:8000/docs`
- Health check: `GET http://localhost:8000/health` -> `{"status":"ok","service":"dcsre-backend"}`

### Local Frontend Setup
```powershell
cd Digital-Crime-Scene-Reconstruction-Engine\frontend
npm install
npm run dev        # Starts Vite dev server on http://localhost:3000 with /api proxy
npm run build      # Builds production bundle to frontend/dist/
```

### Run Backend Tests
```powershell
cd Digital-Crime-Scene-Reconstruction-Engine\backend
.\venv\Scripts\pytest.exe -q
```

### Docker Compose (Full Stack + PostgreSQL 15)
```bash
docker-compose up --build
```
Exposes **Frontend** on `http://localhost:3000`, **Backend API** on `http://localhost:8000`, and **PostgreSQL 15** (`dcsre`) with persistent `postgres_data` and `./backend/uploads` volumes.
