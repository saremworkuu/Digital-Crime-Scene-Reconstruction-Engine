# User schemas
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.db.models.user import UserRole


class UserUpdate(BaseModel):
    username: str | None = Field(default=None, min_length=3, max_length=50)
    email: EmailStr | None = None
    role: UserRole | None = None

    model_config = ConfigDict(extra="forbid")

