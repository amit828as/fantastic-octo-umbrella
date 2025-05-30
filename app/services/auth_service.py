from typing import Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
import logging

from app.models.admin import Admin
from app.models.organization import Organization
from app.utils.auth_utils import AuthUtils
from app.utils.password_utils import PasswordUtils
from app.schemas.auth import LoginRequest, LoginResponse

# Configure logging
logger = logging.getLogger(__name__)


class AuthService:
    """Service for handling authentication operations"""
    
    @staticmethod
    def authenticate_admin(
        db: Session, 
        login_request: LoginRequest
    ) -> Tuple[bool, str, Optional[LoginResponse]]:
        """
        Authenticate an admin user and generate JWT token.
        
        Args:
            db: Database session
            login_request: Login credentials
            
        Returns:
            Tuple of (success: bool, message: str, login_response: Optional[LoginResponse])
        """
        try:
            # Find admin by email
            admin = db.query(Admin).filter(
                Admin.email.ilike(login_request.email)
            ).first()
            
            if not admin:
                logger.warning(f"Login attempt with non-existent email: {login_request.email}")
                return False, "Invalid email or password", None
            
            # Verify password
            if not PasswordUtils.verify_password(login_request.password, admin.password_hash):
                logger.warning(f"Failed login attempt for admin: {admin.email}")
                return False, "Invalid email or password", None
            
            # Get organization details
            organization = db.query(Organization).filter(
                Organization.id == admin.organization_id
            ).first()
            
            if not organization:
                logger.error(f"Admin {admin.email} has invalid organization_id: {admin.organization_id}")
                return False, "Account configuration error", None
            
            # Generate token
            token_data = AuthUtils.create_admin_token_data(
                admin_id=admin.id,
                email=admin.email,
                organization_id=organization.id,
                organization_name=organization.name
            )
            
            access_token = AuthUtils.generate_token(token_data)
            
            # Create response
            login_response = LoginResponse(
                access_token=access_token,
                token_type="bearer",
                expires_in=AuthUtils.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                admin_id=admin.id,
                email=admin.email,
                organization_id=organization.id,
                organization_name=organization.name
            )
            
            logger.info(f"Successful login for admin: {admin.email}")
            return True, "Authentication successful", login_response
            
        except SQLAlchemyError as e:
            logger.error(f"Database error during authentication: {str(e)}")
            return False, "Authentication service error", None
        except Exception as e:
            logger.error(f"Unexpected error during authentication: {str(e)}")
            return False, "Authentication error", None
    
    @staticmethod
    def get_admin_by_token(db: Session, token: str) -> Tuple[bool, str, Optional[Admin]]:
        """
        Get admin user from JWT token.
        
        Args:
            db: Database session
            token: JWT token
            
        Returns:
            Tuple of (success: bool, message: str, admin: Optional[Admin])
        """
        try:
            # Extract user info from token
            user_info = AuthUtils.get_current_user(token)
            admin_id = user_info.get("admin_id")
            
            if not admin_id:
                return False, "Invalid token: missing admin ID", None
            
            # Find admin in database
            admin = db.query(Admin).filter(Admin.id == admin_id).first()
            
            if not admin:
                logger.warning(f"Token contains non-existent admin ID: {admin_id}")
                return False, "Admin account not found", None
            
            # Verify token email matches database
            token_email = user_info.get("email")
            if token_email and token_email.lower() != admin.email.lower():
                logger.warning(f"Token email mismatch for admin {admin_id}")
                return False, "Token validation failed", None
            
            return True, "Admin authenticated", admin
            
        except Exception as e:
            logger.error(f"Error getting admin by token: {str(e)}")
            return False, "Token validation error", None
    
    @staticmethod
    def validate_admin_organization_access(
        admin: Admin, 
        required_organization_id: Optional[int] = None
    ) -> Tuple[bool, str]:
        """
        Validate that an admin has access to a specific organization.
        
        Args:
            admin: Admin user object
            required_organization_id: Optional organization ID to check access for
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # If no specific organization required, admin is valid
            if required_organization_id is None:
                return True, "Access granted"
            
            # Check if admin belongs to the required organization
            if admin.organization_id != required_organization_id:
                logger.warning(
                    f"Admin {admin.email} attempted to access organization {required_organization_id} "
                    f"but belongs to organization {admin.organization_id}"
                )
                return False, "Access denied: insufficient organization permissions"
            
            return True, "Organization access granted"
            
        except Exception as e:
            logger.error(f"Error validating organization access: {str(e)}")
            return False, "Access validation error"
    
    @staticmethod
    def refresh_admin_token(
        db: Session, 
        current_token: str
    ) -> Tuple[bool, str, Optional[LoginResponse]]:
        """
        Refresh an admin's JWT token.
        
        Args:
            db: Database session
            current_token: Current JWT token
            
        Returns:
            Tuple of (success: bool, message: str, login_response: Optional[LoginResponse])
        """
        try:
            # Get admin from current token
            success, message, admin = AuthService.get_admin_by_token(db, current_token)
            
            if not success or not admin:
                return False, f"Token refresh failed: {message}", None
            
            # Get organization details
            organization = db.query(Organization).filter(
                Organization.id == admin.organization_id
            ).first()
            
            if not organization:
                return False, "Organization not found", None
            
            # Generate new token
            token_data = AuthUtils.create_admin_token_data(
                admin_id=admin.id,
                email=admin.email,
                organization_id=organization.id,
                organization_name=organization.name
            )
            
            access_token = AuthUtils.generate_token(token_data)
            
            # Create response
            login_response = LoginResponse(
                access_token=access_token,
                token_type="bearer",
                expires_in=AuthUtils.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                admin_id=admin.id,
                email=admin.email,
                organization_id=organization.id,
                organization_name=organization.name
            )
            
            logger.info(f"Token refreshed for admin: {admin.email}")
            return True, "Token refreshed successfully", login_response
            
        except Exception as e:
            logger.error(f"Error refreshing token: {str(e)}")
            return False, "Token refresh error", None 