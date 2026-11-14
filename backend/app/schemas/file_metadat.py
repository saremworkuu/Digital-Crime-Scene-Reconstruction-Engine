
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class FileMetadataCreate(BaseModel):
    evidence_id: uuid.UUID
    file_path: str = Field(min_length=1, max_length=4096)
    file_size: int | None = Field(default=None, ge=0)
    file_hash: str | None = Field(default=None, max_length=128)
    hash_algorithm: str | None = Field(default=None, max_length=20)
    created_time: datetime | None = None
    modified_time: datetime | None = None
    accessed_time: datetime | None = None
    deleted_time: datetime | None = None


class FileMetadataResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID
    evidence_id: uuid.UUID
    file_path: str
    file_size: int | None
    file_hash: str | None
    hash_algorithm: str | None
    created_time: datetime | None
    modified_time: datetime | None
    accessed_time: datetime | None
    deleted_time: datetime | None
