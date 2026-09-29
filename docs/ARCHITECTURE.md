# Architecture

## System Overview
The Digital Crime Scene Reconstruction Engine is a full-stack application for analyzing and reconstructing digital crime scenes from various log sources.

## Components

### Frontend
- React with TypeScript
- Vite build tool
- React Router for navigation
- State management with Zustand

### Backend
- FastAPI framework
- SQLAlchemy ORM
- PostgreSQL database
- Alembic migrations

### Services
- Log ingestion and parsing
- Event normalization
- Correlation engine
- Detection rules
- Timeline generation
- Attack graph construction
- Report generation

## Data Flow
1. Evidence upload → Parser → Normalizer → Database
2. Database → Correlation Engine → Detection Service
3. Detection Service → Timeline/Graph Services → Frontend
