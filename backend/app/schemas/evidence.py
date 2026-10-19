
# Evidence schemas
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict
from app.db.models.evidence import ParsingStatus


class EvidenceResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    uploaded_by: uuid.UUID
    filename: str
    description: str
    file_type: str
    file_size: int
    sha256_hash: str
    uploaded_at: datetime
    parsing_status: ParsingStatus
    parsing_error: str | None = None

    model_config = ConfigDict(from_attributes=True)


class EvidenceUploadResult(BaseModel):
    filename: str
    status: str
    evidence: EvidenceResponse | None = None
    error: str | None = None


class EvidenceBatchResponse(BaseModel):
    total: int
    successful: int
    failed: int
    results: list[EvidenceUploadResult]
