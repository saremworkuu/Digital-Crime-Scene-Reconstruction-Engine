# Security Verification Checklist (NIST SP 800-86)

- [x] Evidence storage isolated outside web-servable root
- [x] Pre-ingestion SHA-256 integrity calculation
- [x] Enforce read-only storage permissions (0440)
- [x] Common Event Schema normalizes timestamps to ISO 8601 UTC
- [x] Audit logs record user ID, action, target, timestamp, and IP address
- [x] Cross-Site Scripting (XSS) prevention: Raw event data strictly rendered as escaped text
- [x] API routes enforce RBAC (Admin, Investigator, Viewer)
- [x] Sensitive parameters excluded from client query strings
- [x] Rate limiting & file size limits enforced (100MB max)
