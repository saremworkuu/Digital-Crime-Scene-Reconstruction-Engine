# Database Schema

## Tables

### users
- id (UUID, PK)
- username (VARCHAR, unique)
- email (VARCHAR, unique)
- hashed_password (VARCHAR)
- role (ENUM)
- created_at (TIMESTAMP)
- updated_at (TIMESTAMP)

### cases
- id (UUID, PK)
- name (VARCHAR)
- description (TEXT)
- status (ENUM)
- created_by (UUID, FK)
- created_at (TIMESTAMP)
- updated_at (TIMESTAMP)

### evidence
- id (UUID, PK)
- case_id (UUID, FK)
- filename (VARCHAR)
- file_type (VARCHAR)
- file_size (INTEGER)
- uploaded_at (TIMESTAMP)

### events
- id (UUID, PK)
- case_id (UUID, FK)
- evidence_id (UUID, FK)
- timestamp (TIMESTAMP)
- event_type (VARCHAR)
- source (VARCHAR)
- details (JSONB)

### detections
- id (UUID, PK)
- case_id (UUID, FK)
- rule_name (VARCHAR)
- severity (ENUM)
- description (TEXT)
- detected_at (TIMESTAMP)

### entities
- id (UUID, PK)
- case_id (UUID, FK)
- type (VARCHAR)
- name (VARCHAR)
- attributes (JSONB)

### relationships
- id (UUID, PK)
- case_id (UUID, FK)
- source_entity_id (UUID, FK)
- target_entity_id (UUID, FK)
- relationship_type (VARCHAR)

### reports
- id (UUID, PK)
- case_id (UUID, FK)
- title (VARCHAR)
- content (TEXT)
- generated_at (TIMESTAMP)

### audit_log
- id (UUID, PK)
- user_id (UUID, FK)
- action (VARCHAR)
- resource (VARCHAR)
- timestamp (TIMESTAMP)
