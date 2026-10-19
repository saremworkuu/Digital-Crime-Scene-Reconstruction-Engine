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
