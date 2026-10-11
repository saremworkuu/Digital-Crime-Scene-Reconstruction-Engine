# Evidence schemas
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict,Field

class EvidenceCreate(BaseModel):
    case_id:uuid.UUID
    filename:str=Field(min_length=1,max_length=255)
    file_type:str=Field(min_length=1,max_length=255)
    file_size:int=Field(gt=0)

class EvidenceResponse(BaseModel):
    id:uuid.UUID
    case_id:uuid.UUID
    filename:str
    file_type:str
    file_size:int
    uploaded_at:datetime

    model_config=ConfigDict(from_attributes=True)