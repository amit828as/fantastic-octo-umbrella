from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from typing import Annotated

from app.database.connection import get_db
from app.schemas.auth import LoginRequest, LoginResponse, LoginError, TokenValidationResponse
from app.services.auth_service import AuthService
from app.utils.auth_utils import AuthUtils
from app.dependencies.auth import get_current_admin, get_current_user_info
from app.models.admin import Admin

# Create the authentication router
router = APIRouter(
    prefix="/api/v1/auth",
    tags=["authentication"],
    responses={
        500: {"description": "Internal Server Error"},
        400: {"description": "Bad Request"},
        401: {"description": "Unauthorized"}
    }
)


@router.post(
    "/admin/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Admin Login",
    description="Authenticate admin user and receive JWT token",
    responses={
        200: {
            "description": "Login successful",
            "model": LoginResponse
        },
        401: {
            "description": "Authentication failed", 
            "model": LoginError,
            "content": {
                "application/json": {
                    "example": {
                        "error": "Authentication Failed",
                        "message": "Invalid email or password",
                        "error_type": "authentication_error"
                    }
                }
            }
        },
        400: {
            "description": "Invalid input data",
            "model": LoginError,
            "content": {
                "application/json": {
                    "example": {
                        "error": "Validation Error",
                        "message": "Email and password are required",
                        "error_type": "validation_error"
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "model": LoginError,
            "content": {
                "application/json": {
                    "example": {
                        "error": "Internal Server Error", 
                        "message": "An unexpected error occurred",
                        "error_type": "server_error"
                    }
                }
            }
        }
    }
)
async def admin_login(
    login_request: LoginRequest,
    db: Annotated[Session, Depends(get_db)]
) -> LoginResponse:
    """
    Authenticate an admin user with email and password.
    
    Returns a JWT token that can be used for subsequent authenticated requests.
    The token expires after 30 minutes by default.
    
    Args:
        login_request: Login credentials (email and password)
        db: Database session dependency
        
    Returns:
        LoginResponse with JWT token and user information
        
    Raises:
        HTTPException: 401 for authentication failure, 400 for validation errors, 500 for server errors
    """
    try:
        # Authenticate the admin
        success, message, login_response = AuthService.authenticate_admin(db, login_request)
        
        if not success:
            # Determine the appropriate error type and status code
            if "Invalid email or password" in message:
                error_type = "authentication_error"
                status_code = status.HTTP_401_UNAUTHORIZED
            elif "configuration error" in message.lower():
                error_type = "configuration_error"
                status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            else:
                error_type = "authentication_error"
                status_code = status.HTTP_401_UNAUTHORIZED
            
            raise HTTPException(
                status_code=status_code,
                detail={
                    "error": "Authentication Failed",
                    "message": message,
                    "error_type": error_type
                }
            )
        
        return login_response
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        # Handle unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Internal Server Error",
                "message": "An unexpected error occurred during authentication",
                "error_type": "server_error"
            }
        )


@router.post(
    "/validate-token",
    response_model=TokenValidationResponse,
    status_code=status.HTTP_200_OK,
    summary="Validate JWT Token",
    description="Validate a JWT token and return user information",
    responses={
        200: {
            "description": "Token validation result",
            "model": TokenValidationResponse
        },
        400: {
            "description": "Invalid request format",
            "model": LoginError
        },
        500: {
            "description": "Internal server error",
            "model": LoginError
        }
    }
)
async def validate_token(
    db: Annotated[Session, Depends(get_db)],
    authorization: str = Header(..., description="Authorization header with Bearer token")
) -> TokenValidationResponse:
    """
    Validate a JWT token and return user information.
    
    This endpoint can be used by client applications to verify if a token is still valid
    and to get current user information.
    
    Args:
        authorization: Authorization header value ("Bearer <token>")
        db: Database session dependency
        
    Returns:
        TokenValidationResponse with validation result and user information
    """
    try:
        # Extract token from Authorization header
        token = AuthUtils.extract_bearer_token(authorization)
        
        # Get admin information from token
        success, message, admin = AuthService.get_admin_by_token(db, token)
        
        if not success:
            return TokenValidationResponse(
                valid=False,
                user_id=None,
                admin_id=None,
                email=None,
                organization_id=None,
                organization_name=None,
                expires_at=None
            )
        
        # Get user info from token
        user_info = AuthUtils.get_current_user(token)
        
        return TokenValidationResponse(
            valid=True,
            user_id=user_info.get("user_id"),
            admin_id=user_info.get("admin_id"),
            email=user_info.get("email"),
            organization_id=user_info.get("organization_id"),
            organization_name=user_info.get("organization_name"),
            expires_at=user_info.get("token_expires_at")
        )
        
    except HTTPException as e:
        # Token validation failed
        return TokenValidationResponse(
            valid=False,
            user_id=None,
            admin_id=None,
            email=None,
            organization_id=None,
            organization_name=None,
            expires_at=None
        )
    except Exception as e:
        # Handle unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Internal Server Error",
                "message": "An unexpected error occurred during token validation",
                "error_type": "server_error"
            }
        )


@router.post(
    "/refresh-token",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh JWT Token",
    description="Refresh an existing JWT token with a new expiration time",
    responses={
        200: {
            "description": "Token refreshed successfully",
            "model": LoginResponse
        },
        401: {
            "description": "Invalid or expired token",
            "model": LoginError
        },
        500: {
            "description": "Internal server error",
            "model": LoginError
        }
    }
)
async def refresh_token(
    db: Annotated[Session, Depends(get_db)],
    authorization: str = Header(..., description="Authorization header with Bearer token")
) -> LoginResponse:
    """
    Refresh a JWT token with a new expiration time.
    
    This endpoint allows clients to extend their authentication session without
    requiring the user to log in again.
    
    Args:
        authorization: Authorization header value ("Bearer <token>")
        db: Database session dependency
        
    Returns:
        LoginResponse with new JWT token and user information
        
    Raises:
        HTTPException: 401 for invalid/expired tokens, 500 for server errors
    """
    try:
        # Extract token from Authorization header
        token = AuthUtils.extract_bearer_token(authorization)
        
        # Refresh the token
        success, message, login_response = AuthService.refresh_admin_token(db, token)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "Token Refresh Failed",
                    "message": message,
                    "error_type": "authentication_error"
                }
            )
        
        return login_response
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        # Handle unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Internal Server Error",
                "message": "An unexpected error occurred during token refresh",
                "error_type": "server_error"
            }
        )


@router.get(
    "/health",
    summary="Authentication Service Health Check",
    description="Check if the authentication service is operational"
)
async def auth_health():
    """Health check endpoint for the authentication service"""
    return {
        "status": "healthy",
        "service": "authentication",
        "version": "1.0.0"
    }


@router.get(
    "/me",
    summary="Get Current User Info",
    description="Get information about the currently authenticated admin user",
    responses={
        200: {
            "description": "Current user information",
            "content": {
                "application/json": {
                    "example": {
                        "admin_id": 1,
                        "email": "admin@acmecorp.com",
                        "organization_id": 1,
                        "user_type": "admin"
                    }
                }
            }
        },
        401: {
            "description": "Unauthorized - invalid or missing token",
            "model": LoginError
        }
    }
)
async def get_me(
    user_info: Annotated[dict, Depends(get_current_user_info)]
):
    """
    Get information about the currently authenticated admin user.
    
    This endpoint requires a valid JWT token in the Authorization header.
    
    Args:
        user_info: Current user information from authentication dependency
        
    Returns:
        dict: Current user information
    """
    return user_info


@router.get(
    "/protected-test",
    summary="Protected Endpoint Test",
    description="Test endpoint that requires authentication",
    responses={
        200: {
            "description": "Access granted",
            "content": {
                "application/json": {
                    "example": {
                        "message": "Access granted to protected resource",
                        "admin_email": "admin@acmecorp.com",
                        "organization_id": 1
                    }
                }
            }
        },
        401: {
            "description": "Unauthorized - invalid or missing token",
            "model": LoginError
        }
    }
)
async def protected_test(
    current_admin: Annotated[Admin, Depends(get_current_admin)]
):
    """
    Test endpoint that requires authentication.
    
    This endpoint demonstrates how to protect routes using the authentication dependency.
    
    Args:
        current_admin: Current authenticated admin from dependency
        
    Returns:
        dict: Success message with admin information
    """
    return {
        "message": "Access granted to protected resource",
        "admin_email": current_admin.email,
        "organization_id": current_admin.organization_id,
        "timestamp": "2025-01-30T08:00:00Z"
    } 