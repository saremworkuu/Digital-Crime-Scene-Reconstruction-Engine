# Auth schemas
from pydantic import BaseModel, EmailStr, Field, ConfigDict

class LoginRequest(BaseModel):
    email:EmailStr
    password:str=Field(min_length=8)


class SignupRequest(BaseModel):
    username:str=Field(min_length=3,max_length=50)
    email:EmailStr
    password:str=Field(min_length=8,max_length=128)

class TokenResponse(BaseModel):
    access_token:str
    token_type:str="bearer"


class UserResponse(BaseModel):
    id: str
    username: str
    email: EmailStr
    role: str
    is_active: bool

    model_config = ConfigDict(from_attributes=True)
