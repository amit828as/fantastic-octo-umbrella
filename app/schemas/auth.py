from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import Optional


class LoginRequest(BaseModel):
    """Schema for admin login request"""
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "admin@acmecorp.com",
                "password": "SecurePassword123!"
            }
        }
    )
    
    email: EmailStr = Field(description="Admin email address")
    password: str = Field(min_length=8, description="Admin password")


class LoginResponse(BaseModel):
    """Schema for successful login response"""
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 1800,
                "admin_id": 1,
                "email": "admin@acmecorp.com",
                "organization_id": 1,
                "organization_name": "Acme Corporation"
            }
        }
    )
    
    access_token: str = Field(description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(description="Token expiration time in seconds")
    admin_id: int = Field(description="Admin user ID")
    email: str = Field(description="Admin email address")
    organization_id: int = Field(description="Organization ID")
    organization_name: str = Field(description="Organization name")


class LoginError(BaseModel):
    """Schema for login error response"""
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "error": "Authentication Failed",
                "message": "Invalid email or password",
                "error_type": "authentication_error"
            }
        }
    )
    
    error: str = Field(description="Error type")
    message: str = Field(description="Error message")
    error_type: str = Field(description="Specific error category")


class TokenValidationResponse(BaseModel):
    """Schema for token validation response"""
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "valid": True,
                "user_id": "1",
                "admin_id": 1,
                "email": "admin@acmecorp.com",
                "organization_id": 1,
                "organization_name": "Acme Corporation",
                "expires_at": 1748594866
            }
        }
    )
    
    valid: bool = Field(description="Whether the token is valid")
    user_id: Optional[str] = Field(None, description="User ID from token")
    admin_id: Optional[int] = Field(None, description="Admin ID from token") 
    email: Optional[str] = Field(None, description="Email from token")
    organization_id: Optional[int] = Field(None, description="Organization ID from token")
    organization_name: Optional[str] = Field(None, description="Organization name from token")
    expires_at: Optional[int] = Field(None, description="Token expiration timestamp") 