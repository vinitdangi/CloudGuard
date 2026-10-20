"""Pydantic request and response schemas for the CloudGuard API."""

import re

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from cloudguard.aws.configuration import AUTH_METHODS, AWS_REGIONS


class SignupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    email: EmailStr
    password: str = Field(min_length=8, max_length=1024, repr=False)
    confirmation: str = Field(min_length=8, max_length=1024, repr=False)


class SignupResponse(BaseModel):
    authenticated: bool = False
    email: EmailStr
    message: str


class EmailVerificationRequest(BaseModel):
    email: EmailStr | None = None
    identifier: str | None = Field(default=None, min_length=1, max_length=254)
    otp: str = Field(pattern=r"^\d{6}$")

    @model_validator(mode="after")
    def require_email_or_identifier(self):
        if (self.email is None) == (self.identifier is None):
            raise ValueError("Provide exactly one email or username.")
        return self


class ResendEmailVerificationRequest(BaseModel):
    email: EmailStr | None = None
    identifier: str | None = Field(default=None, min_length=1, max_length=254)

    @model_validator(mode="after")
    def require_email_or_identifier(self):
        if (self.email is None) == (self.identifier is None):
            raise ValueError("Provide exactly one email or username.")
        return self


class EmailVerificationResponse(BaseModel):
    verified: bool
    message: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr | None = None
    identifier: str | None = Field(default=None, min_length=1, max_length=254)

    @model_validator(mode="after")
    def require_email_or_identifier(self):
        if (self.email is None) == (self.identifier is None):
            raise ValueError("Provide exactly one email or username.")
        return self


class PasswordResetRequest(BaseModel):
    token: str = Field(min_length=1, max_length=256, repr=False)
    password: str = Field(min_length=1, max_length=1024, repr=False)
    confirmation: str = Field(min_length=1, max_length=1024, repr=False)


class PasswordResetResponse(BaseModel):
    message: str


class GenericMessageResponse(BaseModel):
    message: str


class LoginRequest(BaseModel):
    login: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=1024, repr=False)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: EmailStr
    created_at: str


class AWSConnectionRequest(BaseModel):
    auth_method: str = Field(min_length=1, max_length=64)
    region: str = Field(min_length=1, max_length=32)
    access_key_id: str = Field(default="", max_length=128, repr=False)
    secret_access_key: str = Field(default="", max_length=1024, repr=False)

    @field_validator("auth_method")
    @classmethod
    def validate_auth_method(cls, value: str) -> str:
        if value not in AUTH_METHODS:
            raise ValueError("Choose a supported AWS authentication method.")
        return value

    @field_validator("region")
    @classmethod
    def validate_region(cls, value: str) -> str:
        if value not in AWS_REGIONS:
            raise ValueError("Choose a supported AWS region.")
        return value

    @model_validator(mode="after")
    def validate_access_key_credentials(self):
        if self.auth_method == "Access Key":
            access_key_id = self.access_key_id.strip()
            if not re.fullmatch(r"[A-Za-z0-9]{16,128}", access_key_id):
                raise ValueError("Enter a valid AWS Access Key ID.")
            if len(self.secret_access_key.strip()) < 16 or any(
                character.isspace() for character in self.secret_access_key
            ):
                raise ValueError("Enter a valid AWS Secret Access Key.")
        return self


class AWSConnectionResponse(BaseModel):
    connected: bool
    account_id: str | None = None
    region: str
    message: str
