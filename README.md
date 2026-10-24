# Digital Crime Scene Reconstruction Engine (DCSRE)

A cybersecurity and digital forensics system that reconstructs and visualizes cyber incidents from collected digital evidence.

## Architecture

```
dcsre/
├── frontend/             # React SPA (TypeScript + Tailwind CSS + Lucide)
│   ├── src/
│   │   ├── pages/        # Login, Dashboard, Cases, CaseDetail, Evidence, Timeline, AttackGraph, Detections, Reports, AuditLog
│   │   ├── components/   # TimelineView, GraphView, EventTable, FilterBar, UploadDropzone, MitreBadge, SeverityTag
│   │   ├── services/     # In-browser SHA-256 hasher, multi-format parsers, correlation & graph builders
│   │   ├── store/        # Unified application state & scenario loader
│   │   ├── types/        # Common Event Schema & data models
│   │   └── sample-data/  # Pre-packaged synthetic attack scenarios & Sigma rules
│   └── package.json
```

## Quick Start

### Running the Application
```bash
cd frontend
npm install
npm run dev
```
Open your browser at **http://localhost:3000** to view the application with all pages, 3D visualization, forensic workspace, and responsive layout.

### Default User Credentials:
- **System Administrator**: `saremworkuu@gmail.com` / `Admin@2026!`
- **Lead Investigator**: `investigator@dcsre.corp` / `Investigator#2026`
Key Features

1. Case Management

DCSRE provides a centralised case workspace for managing digital forensic investigations.

Each investigation can contain information such as:

-Case identification

-Investigation status

-Incident classification

-Case description

-Investigation timeline
-attack correlations

Final reports

This provides investigators with a structured location for managing the complete investigation lifecycle.

2. Digital Evidence Management

The evidence workspace allows investigators to work with collected digital artefacts.

Evidence may include:

-System logs

-Authentication logs

-Network logs

-Endpoint events

-Security alerts

-Browser artefacts

-Process information

-File metadata

-IP addresses

-Domains
Evidence Integrity

DCSRE includes an in-browser SHA-256 hashing capability to help establish an integrity value for uploaded evidence.

A SHA-256 hash can be used to:

-Calculate a fingerprint of the evidence.

-Record the fingerprint during investigation.

-Compare the fingerprint later.

-Detect unexpected modifications to the evidence.
 Common Event Schema

Different security tools often represent the same activity using different field names and structures.

DCSRE therefore uses a Common Event Schema to provide a consistent representation of investigation events.

A normalised event can contain information such as:

-Timestamp

-Event type

-Source

-Destination

Source IP

Destination IP

-User

-Host
Installation

Clone the repository:

git clone <https://github.com/saremworkuu/Digital-Crime-Scene-Reconstruction-Engine>

-Enter the project directory;

cd dcsre

-Enter the frontend directory:

cd frontend

-Install the dependencies:

npm install

Security Considerations

DCSRE is designed for security and forensic investigation purposes. However, the application should be deployed using appropriate security controls.

Important considerations include:

-Never expose investigation data publicly.

-Protect investigator accounts.

-Use strong authentication credentials.

-Do not commit passwords or API keys to Git.

-Do not commit .env files containing secrets.

-Protect uploaded evidence from unauthorised access.

-Validate uploaded files before processing.

-Restrict access to sensitive cases.

-Maintain audit records.

-Use HTTPS in production.

-Follow organisational evidence-handling procedures.

-Preserve original evidence whenever possible.

-Use hashes to support evidence integrity verification.
-Potential future improvements include:

-Backend API

-Persistent database

-Multi-user investigation management

-Role-based access control

-Advanced evidence acquisition

-Chain-of-custody management

-Automated IOC extraction

-Threat intelligence integration

-Advanced event correlation

-Automated attack-path reconstruction

-Additional MITRE ATT&CK automation
Disclaimer

DCSRE is intended for authorised cybersecurity, digital-forensics, research, education, and incident-response activities.

The platform should only be used with systems, networks, devices, and digital evidence for which the investigator has appropriate authorisation.

The developers are not responsible for misuse of the software or for investigations conducted without proper legal or organisational authority.

