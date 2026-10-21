# Digital Crime Scene Reconstruction Engine

Cyber DFIR platform for reconstructing cyber incidents and supporting **incident response & cybersecurity investigations**.

This MVP focuses on the IR support feature: case lifecycle, response playbooks, task tracking across NIST-style phases, IOC handling with advisory response hints, ATT&CK technique mapping, audit trail, and IR handoff export.

## Stack

- **Backend:** Python FastAPI + SQLAlchemy + SQLite
- **Frontend:** React + TypeScript + Vite

## Quick start

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

API docs: http://127.0.0.1:8000/docs

### Frontend

```bash
cd frontend
npm install
npm run dev
```

UI: http://127.0.0.1:5173

## Incident response workflow

1. Create an investigation with a **Case ID** like `INC-2026-0042` (auto-suggested).
2. Open the case → **Response** tab.
3. Apply a seeded digital-forensics playbook (25 playbooks covering acquisition, malware, BEC, cloud, APT, etc.).
4. Track tasks (todo → in progress → done) and advance case status.
5. Add IOCs with recommended containment hints (advisory only).
6. Map MITRE ATT&CK techniques from timeline evidence.
7. Export an **IR handoff** markdown report for responders/handover.

## API highlights

| Endpoint | Purpose |
|----------|---------|
| `GET/POST /api/cases` | List / create investigations |
| `GET /api/playbooks` | Seeded IR playbooks |
| `POST /api/cases/{id}/apply-playbook` | Materialize playbook tasks |
| `GET/PATCH /api/cases/{id}/tasks` | Response task board |
| `GET/POST /api/cases/{id}/iocs` | Indicator tracking |
| `GET/POST /api/cases/{id}/techniques` | ATT&CK hits |
| `GET /api/cases/{id}/response-summary` | Phase progress + narrative |
| `GET /api/cases/{id}/reports/ir-handoff` | Markdown handoff export |

## Safety note

Response actions are **checklists and investigation tracking only**. The engine does not execute blocking, isolation, or exploit code against live systems.
