from fastapi import Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from typing import Annotated, Optional

from app.database.connection import get_db
from app.models.admin import Admin
from app.services.auth_service import AuthService
from app.utils.auth_utils import AuthUtils


async def get_current_admin(
    db: Annotated[Session, Depends(get_db)],
    authorization: str = Header(..., description="Authorization header with Bearer token")
) -> Admin:
    """
    Dependency to get the current authenticated admin user.
    
    Args:
        db: Database session
        authorization: Authorization header with Bearer token
        
    Returns:
        Admin: The authenticated admin user
        
    Raises:
        HTTPException: 401 if authentication fails
    """
    try:
        # Extract token from Authorization header
        token = AuthUtils.extract_bearer_token(authorization)
        
        # Get admin from token
        success, message, admin = AuthService.get_admin_by_token(db, token)
        
        if not success or not admin:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return admin
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication error",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_admin_optional(
    db: Annotated[Session, Depends(get_db)],
    authorization: Optional[str] = Header(None, description="Optional Authorization header with Bearer token")
) -> Optional[Admin]:
    """
    Dependency to optionally get the current authenticated admin user.
    
    Args:
        db: Database session
        authorization: Optional Authorization header with Bearer token
        
    Returns:
        Optional[Admin]: The authenticated admin user or None if not authenticated
    """
    if not authorization:
        return None
    
    try:
        # Extract token from Authorization header
        token = AuthUtils.extract_bearer_token(authorization)
        
        # Get admin from token
        success, message, admin = AuthService.get_admin_by_token(db, token)
        
        if success and admin:
            return admin
        
        return None
        
    except Exception:
        # Return None for any authentication errors in optional dependency
        return None


def require_organization_access(required_organization_id: int):
    """
    Dependency factory to require access to a specific organization.
    
    Args:
        required_organization_id: The organization ID that the admin must have access to
        
    Returns:
        Dependency function that validates organization access
    """
    async def organization_access_dependency(
        current_admin: Annotated[Admin, Depends(get_current_admin)]
    ) -> Admin:
        """
        Validate that the current admin has access to the required organization.
        
        Args:
            current_admin: The authenticated admin user
            
        Returns:
            Admin: The admin user if they have access
            
        Raises:
            HTTPException: 403 if access is denied
        """
        success, message = AuthService.validate_admin_organization_access(
            current_admin, required_organization_id
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=message
            )
        
        return current_admin
    
    return organization_access_dependency


async def get_current_user_info(
    current_admin: Annotated[Admin, Depends(get_current_admin)]
) -> dict:
    """
    Dependency to get current user information as a dictionary.
    
    Args:
        current_admin: The authenticated admin user
        
    Returns:
        dict: User information dictionary
    """
    return {
        "admin_id": current_admin.id,
        "email": current_admin.email,
        "organization_id": current_admin.organization_id,
        "user_type": "admin"
    } 