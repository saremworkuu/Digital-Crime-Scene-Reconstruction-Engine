# Case schemas

import uuid
from datetime import datetime
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.db.models.case import CaseStatus


class CaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    tags: Optional[List[str]] = Field(default_factory=list)


class CaseResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str] = None
    status: CaseStatus
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime
    
    # Enrichment fields expected by frontend
    tags: List[str] = Field(default_factory=list)
    evidence_count: int = 0
    event_count: int = 0
    detection_count: int = 0
    critical_detection_count: int = 0
    assigned_users: List[str] = Field(default_factory=list)
    owner_id: Optional[str] = None
    owner_name: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class CaseAssignmentCreate(BaseModel):
    user_id: UUID


class CaseAssignMultipleRequest(BaseModel):
    user_ids: List[UUID]


class CaseAssignmentResponse(BaseModel):
    id: UUID
    case_id: UUID
    user_id: UUID
    assigned_by: UUID
    assigned_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaseUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[CaseStatus] = None
    tags: Optional[List[str]] = None