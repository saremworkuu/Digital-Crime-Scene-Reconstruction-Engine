# DCSRE Forensic Threat Model (STRIDE)

## 1. Asset Inventory
- Digital Evidence Files (disk images, EVTX, PCAP, auth.log)
- Case Timelines & Reconstructed Sequences
- Cryptographic Hashes (SHA-256 Chain of Custody)
- Immutable Audit Ledger

## 2. Threat Analysis
- **Spoofing**: Mitigation via JWT authentication, bcrypt passwords, and strict role validation.
- **Tampering**: Mitigation via read-only file permissions (0440), storage isolated from web root, SHA-256 pre-ingest validation, and immutable audit logs.
- **Repudiation**: All examiner actions signed with UTC timestamp, user ID, IP address, and operation payload.
- **Information Disclosure**: Role-based access control (RBAC), multi-tenant case isolation.
- **Denial of Service**: Upload file size ceiling (100MB max per file), streaming chunked parser evaluation.
- **Elevation of Privilege**: Strict backend route role enforcement (`admin`, `investigator`, `viewer`).
