# Contributing to DCSRE

Thank you for your interest in contributing to the Digital Crime Scene Reconstruction Engine!

## Workflow

1. Fork the repository and create your branch from `main`.
2. Ensure backend tests pass (`pytest backend/tests`).
3. Ensure frontend builds and passes linting (`npm run lint` and `npm run build`).
4. Follow forensic integrity rules:
   - Evidence files must never be modified or directly executed.
   - All parser output must strictly adhere to the Common Event Schema.
   - All critical actions must be recorded in the audit log.
5. Submit a pull request referencing relevant issues.
