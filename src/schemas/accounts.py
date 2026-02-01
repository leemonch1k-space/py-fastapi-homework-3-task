from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database.validators import accounts


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return accounts.validate_email(value)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return accounts.validate_password_strength(value)


class UserActivationSchema(BaseModel):
    email: EmailStr
    token: str


class UserLoginSchema(BaseModel):
    email: str
    password: str


class UserReadSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr


class PasswordResetSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteSchema(PasswordResetSchema):
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return accounts.validate_password_strength(value)


class TokenResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str


class RefreshTokenResponseSchema(BaseModel):
    access_token: str
