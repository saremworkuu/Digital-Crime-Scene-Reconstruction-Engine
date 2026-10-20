# Evidence schemas
import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field
from app.db.models.evidence import ParsingStatus


class EvidenceResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    uploaded_by: uuid.UUID
    filename: str
    description: Optional[str] = ""
    file_type: str
    file_size: int
    sha256_hash: str
    uploaded_at: datetime
    parsing_status: ParsingStatus
    parsing_error: Optional[str] = None
    parser_used: Optional[str] = None

    # Convenience aliases matching frontend EvidenceFile
    size_bytes: Optional[int] = None
    status: Optional[str] = None
    uploader_name: Optional[str] = None
    uploader_id: Optional[str] = None
    event_count: int = 0
    raw_sample: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class EvidenceUploadResult(BaseModel):
    filename: str
    status: str
    evidence: Optional[EvidenceResponse] = None
    error: Optional[str] = None


class EvidenceBatchResponse(BaseModel):
    total: int
    successful: int
    failed: int
    results: List[EvidenceUploadResult]


class ReparseRequest(BaseModel):
    parser_type: Optional[str] = None
