# Contributing to Digital Crime Scene Reconstruction Engine

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/dcsre.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Commit your changes: `git commit -m 'Add some feature'`
6. Push to the branch: `git push origin feature/your-feature-name`
7. Open a Pull Request

## Development Setup

### Prerequisites
- Node.js 18+
- Python 3.11+
- Docker and Docker Compose

### Frontend
```bash
cd frontend
npm install
npm run dev
```

### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Using Docker
```bash
docker-compose up
```

## Code Style

### Frontend
- Use TypeScript
- Follow ESLint rules
- Use functional components with hooks
- Keep components small and focused

### Backend
- Follow PEP 8
- Use type hints
- Write docstrings for functions
- Keep functions focused and testable

## Testing

### Frontend
```bash
cd frontend
npm test
```

### Backend
```bash
cd backend
pytest
```

## Pull Request Guidelines

- Write descriptive commit messages
- Update documentation as needed
- Add tests for new features
- Ensure all tests pass
- Update the CHANGELOG if applicable

## Reporting Issues

When reporting issues, please include:
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment details
- Screenshots if applicable

## Questions

Feel free to open an issue for questions or discussions.
