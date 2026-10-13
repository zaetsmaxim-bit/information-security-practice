import re
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, field_validator

NAME_RE = re.compile(r"^[A-Za-zА-Яа-яІіЇїЄєҐґ ',\-]+$")

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=30, pattern=r"^[a-zA-Z0-9_]+$")
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=72)
    full_name: str = Field(..., min_length=2, max_length=100)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v): raise ValueError("Потрібна велика літера")
        if not re.search(r"[a-z]", v): raise ValueError("Потрібна мала літера")
        if not re.search(r"\d", v): raise ValueError("Потрібна цифра")
        return v

    @field_validator("full_name")
    @classmethod
    def full_name_allowlist(cls, v: str) -> str:
        if not NAME_RE.match(v): raise ValueError("Тільки літери, пробіл, апостроф, дефіс")
        return v.strip()

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    is_active: bool
    created_at: datetime
    model_config = {"from_attributes": True}

class LoginRequest(BaseModel):
    username: str = Field(..., max_length=30)
    password: str = Field(..., max_length=72)

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenRefreshRequest(BaseModel):
    refresh_token: str

class UserInfo(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    roles: list[str]

class GradeCreate(BaseModel):
    student_id: int = Field(..., gt=0)
    subject_id: int = Field(..., gt=0)
    grade: int = Field(..., ge=0, le=100)
    comment: str | None = Field(None, max_length=500)
