# Auth schemas
from typing import Optional, Any
from pydantic import BaseModel, EmailStr, Field, ConfigDict, model_validator


class LoginRequest(BaseModel):
    email: str = Field(min_length=1, description="Email address or username")
    password: str = Field(min_length=1, description="User password")


class SignupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)


class RegisterRequest(BaseModel):
    name: Optional[str] = None
    username: Optional[str] = None
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)
    role: Optional[str] = "investigator"
    department: Optional[str] = None
    badge_id: Optional[str] = None
    pgp_key: Optional[str] = None


class UserResponse(BaseModel):
    id: str
    username: str
    name: Optional[str] = None
    email: EmailStr
    role: str
    is_active: bool = True
    department: Optional[str] = None
    badge_id: Optional[str] = None
    badgeId: Optional[str] = None
    created_at: Optional[Any] = None

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token: Optional[str] = None
    token_type: str = "bearer"
    user: Optional[UserResponse] = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=6, max_length=128)
    confirm_password: Optional[str] = None


class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    department: Optional[str] = None
    badge_id: Optional[str] = None
    badgeId: Optional[str] = None

    @model_validator(mode="after")
    def sync_badge_fields(self) -> "UpdateProfileRequest":
        if self.badge_id and not self.badgeId:
            self.badgeId = self.badge_id
        elif self.badgeId and not self.badge_id:
            self.badge_id = self.badgeId
        return self


