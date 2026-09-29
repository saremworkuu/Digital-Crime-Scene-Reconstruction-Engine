# API Documentation

## Authentication
POST /api/v1/auth/login
POST /api/v1/auth/logout
POST /api/v1/auth/refresh

## Cases
GET /api/v1/cases
POST /api/v1/cases
GET /api/v1/cases/{id}
PUT /api/v1/cases/{id}
DELETE /api/v1/cases/{id}

## Evidence
GET /api/v1/evidence
POST /api/v1/evidence/upload
GET /api/v1/evidence/{id}
DELETE /api/v1/evidence/{id}

## Events
GET /api/v1/events
GET /api/v1/events/{id}
GET /api/v1/events/search

## Timeline
GET /api/v1/timeline/{case_id}

## Graph
GET /api/v1/graph/{case_id}

## Detections
GET /api/v1/detections
GET /api/v1/detections/{id}

## Reports
GET /api/v1/reports
POST /api/v1/reports
GET /api/v1/reports/{id}

## Audit
GET /api/v1/audit
