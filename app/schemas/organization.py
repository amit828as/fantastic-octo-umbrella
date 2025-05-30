from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict
from typing import Optional
import re


class OrganizationCreateRequest(BaseModel):
    """Schema for organization creation request"""
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "admin@acmecorp.com",
                "password": "SecurePassword123!",
                "organization_name": "Acme Corporation"
            }
        }
    )
    
    email: EmailStr = Field(
        ..., 
        description="Admin user email address",
        json_schema_extra={"example": "admin@example.com"}
    )
    
    password: str = Field(
        ..., 
        min_length=8,
        max_length=128,
        description="Admin user password (minimum 8 characters)",
        json_schema_extra={"example": "SecurePassword123!"}
    )
    
    organization_name: str = Field(
        ..., 
        min_length=2,
        max_length=100,
        description="Organization name",
        json_schema_extra={"example": "Acme Corporation"}
    )
    
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, password):
        """
        Validate password strength requirements:
        - At least 8 characters long
        - Contains at least one uppercase letter
        - Contains at least one lowercase letter  
        - Contains at least one digit
        - Contains at least one special character
        """
        if len(password) < 8:
            raise ValueError('Password must be at least 8 characters long')
        
        if not re.search(r'[A-Z]', password):
            raise ValueError('Password must contain at least one uppercase letter')
        
        if not re.search(r'[a-z]', password):
            raise ValueError('Password must contain at least one lowercase letter')
        
        if not re.search(r'\d', password):
            raise ValueError('Password must contain at least one digit')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValueError('Password must contain at least one special character (!@#$%^&*(),.?":{}|<>)')
        
        return password
    
    @field_validator('organization_name')
    @classmethod
    def validate_organization_name(cls, name):
        """
        Validate organization name:
        - No leading/trailing whitespace
        - No special characters except hyphens, spaces, and periods
        - Cannot be only whitespace
        """
        name = name.strip()
        
        if not name:
            raise ValueError('Organization name cannot be empty or only whitespace')
        
        # Allow letters, numbers, spaces, hyphens, and periods
        if not re.match(r'^[a-zA-Z0-9\s\-\.]+$', name):
            raise ValueError('Organization name can only contain letters, numbers, spaces, hyphens, and periods')
        
        # Don't allow names that are only special characters
        if re.match(r'^[\s\-\.]+$', name):
            raise ValueError('Organization name must contain at least one letter or number')
        
        return name


class OrganizationCreateResponse(BaseModel):
    """Schema for organization creation response"""
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "success": True,
                "message": "Organization created successfully",
                "organization_id": 1,
                "organization_name": "Acme Corporation",
                "admin_email": "admin@acmecorp.com"
            }
        }
    )
    
    success: bool = Field(description="Whether the organization was created successfully")
    message: str = Field(description="Response message")
    organization_id: Optional[int] = Field(None, description="ID of the created organization")
    organization_name: Optional[str] = Field(None, description="Name of the created organization")
    admin_email: Optional[str] = Field(None, description="Email of the admin user")


class OrganizationCreateError(BaseModel):
    """Schema for organization creation error response"""
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "success": False,
                "message": "Organization name already exists",
                "error_type": "duplicate_organization",
                "details": {
                    "organization_name": "Acme Corporation"
                }
            }
        }
    )
    
    success: bool = Field(False, description="Always false for error responses")
    message: str = Field(description="Error message")
    error_type: str = Field(description="Type of error")
    details: Optional[dict] = Field(None, description="Additional error details") 