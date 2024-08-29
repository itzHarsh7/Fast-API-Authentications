from pydantic import BaseModel, EmailStr, Field, validator

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password1: str = Field(..., min_length=8, max_length=16)
    password2: str
    first_name: str = None
    last_name: str = None

    @validator("password2")
    def passwords_match(cls, v, values):
        if 'password1' in values and v != values['password1']:
            raise ValueError("Passwords do not match")
        return v

    @validator("password1")
    def password_strength(cls, v):
        if not any(char.isdigit() for char in v):
            raise ValueError("Password must contain at least one digit")
        if not any(char.isupper() for char in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(char.islower() for char in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(char in "!@#$%^&*()_+-=" for char in v):
            raise ValueError("Password must contain at least one special character")
        return v

class UserLogin(BaseModel):
    username_or_email: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    first_name: str = None
    last_name: str = None

    class Config:
        orm_mode = True
