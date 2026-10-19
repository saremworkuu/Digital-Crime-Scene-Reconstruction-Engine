# Case schemas

import uuid
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.db.models.case import CaseStatus


class CaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None


class CaseResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    status: CaseStatus
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaseAssignmentCreate(BaseModel):
    user_id: UUID


class CaseAssignmentResponse(BaseModel):
    id: UUID
    case_id: UUID
    user_id: UUID
    assigned_by: UUID
    assigned_at: datetime

    model_config = ConfigDict(from_attributes=True)

class CaseUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: CaseStatus | None = None