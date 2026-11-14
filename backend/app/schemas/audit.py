import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditLogResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    case_id: uuid.UUID | None = None
    action: str
    resource: str
    ip_address: str | None = None
    user_agent: str | None = None
    details: dict | list | str | None = None
    timestamp: datetime
    user_name: str | None = None
    user_role: str | None = None
    target_type: str | None = None
    target_id: str | None = None

    model_config = ConfigDict(from_attributes=True)
