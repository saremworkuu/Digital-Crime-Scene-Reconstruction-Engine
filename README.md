# Digital Crime Scene Reconstruction Engine (DCSRE)

A comprehensive web-based application for digital forensic investigators to analyze and reconstruct crime scenes from various log sources.

## Features

- **Case Management**: Create and manage investigation cases
- **Evidence Ingestion**: Upload and parse multiple log formats (auth logs, web logs, EVTX, PCAP, etc.)
- **Timeline Visualization**: Chronological view of events with filtering and zoom capabilities
- **Attack Graph**: Interactive visualization of entity relationships and attack paths
- **Detection Rules**: Pre-configured and custom detection rules based on MITRE ATT&CK
- **Report Generation**: Comprehensive investigation reports with timeline and graphs
- **Audit Logging**: Complete audit trail of all system actions

## Tech Stack

### Frontend
- React 18 with TypeScript
- Vite
- React Router
- Zustand for state management

### Backend
- FastAPI
- SQLAlchemy ORM
- PostgreSQL
- Alembic migrations

## Quick Start

### Using Docker (Recommended)

```bash
docker-compose up
```

Access the application at http://localhost:3000

### Manual Setup

#### Prerequisites
- Node.js 18+
- Python 3.11+
- PostgreSQL 15+

#### Frontend
```bash
cd frontend
npm install
npm run dev
```

#### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [API Documentation](docs/API.md)
- [Database Schema](docs/SCHEMA.md)
- [User Guide](docs/USER_GUIDE.md)
- [Security](security/THREAT_MODEL.md)

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License.

## Security

For security concerns, please see [SECURITY.md](SECURITY.md).
