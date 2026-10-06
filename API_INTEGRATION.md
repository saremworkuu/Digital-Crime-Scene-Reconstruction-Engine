# API Integration Guide

This document provides a comprehensive overview of all API endpoints for frontend-backend integration.

## Base URL

```
Development: http://localhost:8000/api/v1
Production: https://your-domain.com/api/v1
```

## Authentication

All endpoints (except login) require authentication via JWT token in the Authorization header:

```
Authorization: Bearer <jwt_token>
```

---

## Authentication Endpoints

### POST /auth/login
Login user and receive JWT token.

**Request:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response:**
```json
{
  "access_token": "string",
  "token_type": "bearer",
  "user": {
    "id": "uuid",
    "username": "string",
    "email": "string",
    "role": "admin|investigator|analyst"
  }
}
```

### POST /auth/logout
Logout user and invalidate token.

**Request:**
```json
{
  "token": "string"
}
```

**Response:**
```json
{
  "message": "Successfully logged out"
}
```

### POST /auth/refresh
Refresh JWT token.

**Request:**
```json
{
  "refresh_token": "string"
}
```

**Response:**
```json
{
  "access_token": "string",
  "token_type": "bearer"
}
```

---

## User Management Endpoints

### GET /users/me
Get current user profile.

**Response:**
```json
{
  "id": "uuid",
  "username": "string",
  "email": "string",
  "role": "admin|investigator|analyst",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

### PUT /users/me
Update current user profile.

**Request:**
```json
{
  "email": "string",
  "current_password": "string",
  "new_password": "string (optional)"
}
```

**Response:**
```json
{
  "id": "uuid",
  "username": "string",
  "email": "string",
  "role": "admin|investigator|analyst",
  "updated_at": "datetime"
}
```

### GET /users
List all users (admin only).

**Query Parameters:**
- `page`: integer (default: 1)
- `limit`: integer (default: 10)

**Response:**
```json
{
  "users": [
    {
      "id": "uuid",
      "username": "string",
      "email": "string",
      "role": "admin|investigator|analyst",
      "created_at": "datetime"
    }
  ],
  "total": 100,
  "page": 1,
  "limit": 10
}
```

---

## Case Management Endpoints

### GET /cases
List all cases.

**Query Parameters:**
- `page`: integer (default: 1)
- `limit`: integer (default: 10)
- `status`: string (optional: open|closed|archived)
- `search`: string (optional)

**Response:**
```json
{
  "cases": [
    {
      "id": "uuid",
      "name": "string",
      "description": "string",
      "status": "open|closed|archived",
      "created_by": "uuid",
      "created_at": "datetime",
      "updated_at": "datetime",
      "evidence_count": 5
    }
  ],
  "total": 50,
  "page": 1,
  "limit": 10
}
```

### POST /cases
Create a new case.

**Request:**
```json
{
  "name": "string",
  "description": "string",
  "status": "open"
}
```

**Response:**
```json
{
  "id": "uuid",
  "name": "string",
  "description": "string",
  "status": "open",
  "created_by": "uuid",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

### GET /cases/{case_id}
Get case details.

**Response:**
```json
{
  "id": "uuid",
  "name": "string",
  "description": "string",
  "status": "open|closed|archived",
  "created_by": "uuid",
  "created_at": "datetime",
  "updated_at": "datetime",
  "evidence": [
    {
      "id": "uuid",
      "filename": "string",
      "file_type": "string",
      "uploaded_at": "datetime"
    }
  ]
}
```

### PUT /cases/{case_id}
Update case details.

**Request:**
```json
{
  "name": "string (optional)",
  "description": "string (optional)",
  "status": "open|closed|archived (optional)"
}
```

**Response:**
```json
{
  "id": "uuid",
  "name": "string",
  "description": "string",
  "status": "open|closed|archived",
  "updated_at": "datetime"
}
```

### DELETE /cases/{case_id}
Delete a case.

**Response:**
```json
{
  "message": "Case deleted successfully"
}
```

---

## Evidence Management Endpoints

### POST /evidence/upload
Upload evidence file to a case.

**Request:** (multipart/form-data)
- `case_id`: string
- `file`: File
- `description`: string (optional)

**Response:**
```json
{
  "id": "uuid",
  "case_id": "uuid",
  "filename": "string",
  "file_type": "string",
  "file_size": integer,
  "description": "string",
  "uploaded_by": "uuid",
  "uploaded_at": "datetime",
  "status": "processing|parsed|error"
}
```

### GET /evidence
List evidence for a case.

**Query Parameters:**
- `case_id`: string (required)
- `page`: integer (default: 1)
- `limit`: integer (default: 10)

**Response:**
```json
{
  "evidence": [
    {
      "id": "uuid",
      "case_id": "uuid",
      "filename": "string",
      "file_type": "string",
      "file_size": integer,
      "description": "string",
      "uploaded_at": "datetime",
      "status": "processing|parsed|error",
      "event_count": 150
    }
  ],
  "total": 5,
  "page": 1,
  "limit": 10
}
```

### GET /evidence/{evidence_id}
Get evidence details.

**Response:**
```json
{
  "id": "uuid",
  "case_id": "uuid",
  "filename": "string",
  "file_type": "string",
  "file_size": integer,
  "description": "string",
  "uploaded_by": "uuid",
  "uploaded_at": "datetime",
  "status": "processing|parsed|error",
  "parsed_at": "datetime",
  "metadata": {
    "parser": "string",
    "events_extracted": 150,
    "entities_found": 10
  }
}
```

### DELETE /evidence/{evidence_id}
Delete evidence.

**Response:**
```json
{
  "message": "Evidence deleted successfully"
}
```

### POST /evidence/{evidence_id}/reparse
Re-parse evidence file.

**Response:**
```json
{
  "id": "uuid",
  "status": "processing",
  "message": "Re-parsing started"
}
```

---

## Event Endpoints

### GET /events
Query events with filters.

**Query Parameters:**
- `case_id`: string (required)
- `start_time`: datetime (ISO format, optional)
- `end_time`: datetime (ISO format, optional)
- `event_type`: string (optional)
- `source`: string (optional)
- `entity_id`: string (optional)
- `page`: integer (default: 1)
- `limit`: integer (default: 50)

**Response:**
```json
{
  "events": [
    {
      "id": "uuid",
      "case_id": "uuid",
      "evidence_id": "uuid",
      "timestamp": "datetime",
      "event_type": "string",
      "source": "string",
      "description": "string",
      "entities": [
        {
          "id": "uuid",
          "type": "user|system|ip|domain",
          "name": "string"
        }
      ],
      "severity": "low|medium|high|critical",
      "mitre_technique": "string (optional)",
      "raw_data": "object"
    }
  ],
  "total": 1000,
  "page": 1,
  "limit": 50
}
```

### GET /events/{event_id}
Get event details.

**Response:**
```json
{
  "id": "uuid",
  "case_id": "uuid",
  "evidence_id": "uuid",
  "timestamp": "datetime",
  "event_type": "string",
  "source": "string",
  "description": "string",
  "entities": [
    {
      "id": "uuid",
      "type": "user|system|ip|domain",
      "name": "string"
    }
  ],
  "severity": "low|medium|high|critical",
  "mitre_technique": "string",
  "raw_data": "object",
  "related_events": ["uuid"]
}
```

### POST /events/search
Advanced event search.

**Request:**
```json
{
  "case_id": "uuid",
  "query": "string (search query)",
  "filters": {
    "start_time": "datetime",
    "end_time": "datetime",
    "event_types": ["string"],
    "sources": ["string"],
    "severity": ["low|medium|high|critical"]
  },
  "page": 1,
  "limit": 50
}
```

**Response:** (same as GET /events)

---

## Timeline Endpoints

### GET /timeline/{case_id}
Get timeline data for a case.

**Query Parameters:**
- `start_time`: datetime (ISO format, optional)
- `end_time`: datetime (ISO format, optional)
- `zoom_level`: string (optional: hour|day|week|month)

**Response:**
```json
{
  "case_id": "uuid",
  "start_time": "datetime",
  "end_time": "datetime",
  "total_events": 1000,
  "events": [
    {
      "id": "uuid",
      "timestamp": "datetime",
      "event_type": "string",
      "description": "string",
      "severity": "low|medium|high|critical",
      "source": "string"
    }
  ],
  "clusters": [
    {
      "start_time": "datetime",
      "end_time": "datetime",
      "event_count": 50,
      "event_types": ["string"]
    }
  ]
}
```

### GET /timeline/{case_id}/summary
Get timeline summary statistics.

**Response:**
```json
{
  "case_id": "uuid",
  "total_events": 1000,
  "event_types": {
    "authentication": 200,
    "file_access": 150,
    "network": 300,
    "process": 350
  },
  "severity_distribution": {
    "low": 500,
    "medium": 300,
    "high": 150,
    "critical": 50
  },
  "time_range": {
    "start": "datetime",
    "end": "datetime"
  }
}
```

---

## Attack Graph Endpoints

### GET /graph/{case_id}
Get attack graph for a case.

**Response:**
```json
{
  "case_id": "uuid",
  "nodes": [
    {
      "id": "uuid",
      "type": "user|system|ip|domain|file",
      "name": "string",
      "properties": {
        "risk_score": 0.8,
        "compromised": true
      }
    }
  ],
  "edges": [
    {
      "id": "uuid",
      "source": "uuid",
      "target": "uuid",
      "relationship": "string",
      "weight": 0.5,
      "events": ["uuid"]
    }
  ],
  "attack_paths": [
    {
      "path": ["uuid", "uuid", "uuid"],
      "confidence": 0.9,
      "technique": "string"
    }
  ]
}
```

### GET /graph/{case_id}/entities
Get all entities in the graph.

**Query Parameters:**
- `type`: string (optional: user|system|ip|domain|file)

**Response:**
```json
{
  "entities": [
    {
      "id": "uuid",
      "type": "user|system|ip|domain|file",
      "name": "string",
      "first_seen": "datetime",
      "last_seen": "datetime",
      "event_count": 50,
      "risk_score": 0.8
    }
  ]
}
```

### GET /graph/{case_id}/relationships
Get entity relationships.

**Query Parameters:**
- `entity_id`: string (optional)

**Response:**
```json
{
  "relationships": [
    {
      "id": "uuid",
      "source": {
        "id": "uuid",
        "name": "string",
        "type": "string"
      },
      "target": {
        "id": "uuid",
        "name": "string",
        "type": "string"
      },
      "relationship_type": "string",
      "event_count": 10,
      "first_seen": "datetime",
      "last_seen": "datetime"
    }
  ]
}
```

---

## Detection Rules Endpoints

### GET /detections
List detection rules.

**Query Parameters:**
- `page`: integer (default: 1)
- `limit`: integer (default: 10)
- `enabled`: boolean (optional)

**Response:**
```json
{
  "rules": [
    {
      "id": "uuid",
      "name": "string",
      "description": "string",
      "mitre_technique": "string",
      "severity": "low|medium|high|critical",
      "enabled": true,
      "created_at": "datetime"
    }
  ],
  "total": 20,
  "page": 1,
  "limit": 10
}
```

### POST /detections
Create a new detection rule.

**Request:**
```json
{
  "name": "string",
  "description": "string",
  "mitre_technique": "string",
  "severity": "low|medium|high|critical",
  "rule_yaml": "string",
  "enabled": true
}
```

**Response:**
```json
{
  "id": "uuid",
  "name": "string",
  "description": "string",
  "mitre_technique": "string",
  "severity": "low|medium|high|critical",
  "rule_yaml": "string",
  "enabled": true,
  "created_at": "datetime"
}
```

### PUT /detections/{rule_id}
Update detection rule.

**Request:**
```json
{
  "name": "string (optional)",
  "description": "string (optional)",
  "enabled": boolean (optional),
  "rule_yaml": "string (optional)"
}
```

**Response:**
```json
{
  "id": "uuid",
  "name": "string",
  "description": "string",
  "enabled": true,
  "updated_at": "datetime"
}
```

### DELETE /detections/{rule_id}
Delete detection rule.

**Response:**
```json
{
  "message": "Detection rule deleted successfully"
}
```

### POST /detections/{rule_id}/run
Manually run detection rule on a case.

**Request:**
```json
{
  "case_id": "uuid"
}
```

**Response:**
```json
{
  "rule_id": "uuid",
  "case_id": "uuid",
  "status": "running",
  "detections_found": 0
}
```

### GET /detections/{case_id}/results
Get detection results for a case.

**Response:**
```json
{
  "case_id": "uuid",
  "results": [
    {
      "rule_id": "uuid",
      "rule_name": "string",
      "severity": "low|medium|high|critical",
      "detection_count": 5,
      "events": ["uuid"]
    }
  ]
}
```

---

## Report Endpoints

### GET /reports
List reports.

**Query Parameters:**
- `case_id`: string (required)
- `page`: integer (default: 1)
- `limit`: integer (default: 10)

**Response:**
```json
{
  "reports": [
    {
      "id": "uuid",
      "case_id": "uuid",
      "title": "string",
      "generated_by": "uuid",
      "created_at": "datetime",
      "format": "pdf|html"
    }
  ],
  "total": 5,
  "page": 1,
  "limit": 10
}
```

### POST /reports
Generate a new report.

**Request:**
```json
{
  "case_id": "uuid",
  "title": "string",
  "format": "pdf|html",
  "include_timeline": true,
  "include_graph": true,
  "include_detections": true
}
```

**Response:**
```json
{
  "id": "uuid",
  "case_id": "uuid",
  "title": "string",
  "format": "pdf|html",
  "status": "generating",
  "created_at": "datetime"
}
```

### GET /reports/{report_id}
Get report details.

**Response:**
```json
{
  "id": "uuid",
  "case_id": "uuid",
  "title": "string",
  "format": "pdf|html",
  "status": "generating|completed|error",
  "generated_by": "uuid",
  "created_at": "datetime",
  "completed_at": "datetime",
  "download_url": "string"
}
```

### GET /reports/{report_id}/download
Download report file.

**Response:** Binary file (PDF or HTML)

### DELETE /reports/{report_id}
Delete report.

**Response:**
```json
{
  "message": "Report deleted successfully"
}
```

---

## Audit Log Endpoints

### GET /audit
List audit logs.

**Query Parameters:**
- `page`: integer (default: 1)
- `limit`: integer (default: 50)
- `user_id`: string (optional)
- `action`: string (optional)
- `start_time`: datetime (ISO format, optional)
- `end_time`: datetime (ISO format, optional)

**Response:**
```json
{
  "logs": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "username": "string",
      "action": "string",
      "resource_type": "string",
      "resource_id": "string",
      "ip_address": "string",
      "timestamp": "datetime",
      "details": "object"
    }
  ],
  "total": 500,
  "page": 1,
  "limit": 50
}
```

---

## Error Responses

All endpoints may return error responses:

### 400 Bad Request
```json
{
  "detail": "Invalid request data"
}
```

### 401 Unauthorized
```json
{
  "detail": "Could not validate credentials"
}
```

### 403 Forbidden
```json
{
  "detail": "Not enough permissions"
}
```

### 404 Not Found
```json
{
  "detail": "Resource not found"
}
```

### 422 Validation Error
```json
{
  "detail": [
    {
      "loc": ["body", "field_name"],
      "msg": "error message",
      "type": "value_error"
    }
  ]
}
```

### 500 Internal Server Error
```json
{
  "detail": "Internal server error"
}
```

---

## Frontend API Client Implementation

### Base API Client

```typescript
// frontend/src/api/base.ts
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

export async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = localStorage.getItem('access_token');
  
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'API request failed');
  }

  return response.json();
}
```

### Example API Client

```typescript
// frontend/src/api/cases.ts
import { apiRequest } from './base';

export interface Case {
  id: string;
  name: string;
  description: string;
  status: 'open' | 'closed' | 'archived';
  created_at: string;
  updated_at: string;
}

export async function getCases(params?: {
  page?: number;
  limit?: number;
  status?: string;
  search?: string;
}) {
  const queryParams = new URLSearchParams(params as any).toString();
  return apiRequest<{ cases: Case[]; total: number }>(
    `/cases?${queryParams}`
  );
}

export async function createCase(data: {
  name: string;
  description: string;
  status: string;
}) {
  return apiRequest<Case>('/cases', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function updateCase(caseId: string, data: Partial<Case>) {
  return apiRequest<Case>(`/cases/${caseId}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteCase(caseId: string) {
  return apiRequest<{ message: string }>(`/cases/${caseId}`, {
    method: 'DELETE',
  });
}
```

---

## File Upload Example

```typescript
// frontend/src/api/evidence.ts
export async function uploadEvidence(
  caseId: string,
  file: File,
  description?: string
) {
  const formData = new FormData();
  formData.append('case_id', caseId);
  formData.append('file', file);
  if (description) {
    formData.append('description', description);
  }

  const token = localStorage.getItem('access_token');
  const response = await fetch(`${API_BASE_URL}/evidence/upload`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
    body: formData,
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Upload failed');
  }

  return response.json();
}
```

---

## Environment Variables

### Frontend (.env)
```env
VITE_API_BASE_URL=http://localhost:8000/api/v1
```

### Backend (.env)
```env
DATABASE_URL=postgresql://user:password@localhost:5432/dcsre
SECRET_KEY=your-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```
