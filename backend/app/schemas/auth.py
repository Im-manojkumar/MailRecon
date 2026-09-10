from pydantic import BaseModel, EmailStr, ConfigDict
from typing import Optional
import uuid

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    display_name: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class AnalystResponse(BaseModel):
    id: uuid.UUID
    email: str
    display_name: Optional[str] = None
    is_active: bool

    model_config = ConfigDict(from_attributes=True)

