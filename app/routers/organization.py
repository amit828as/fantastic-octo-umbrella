from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, OperationalError
import logging
from typing import Dict, Any

from app.database.connection import get_db
from app.schemas.organization import (
    OrganizationCreateRequest, 
    OrganizationCreateResponse, 
    OrganizationCreateError,
    OrganizationResponse,
    OrganizationError
)
from app.services.organization_service import OrganizationService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/org", tags=["organizations"])


@router.post("/create", 
             response_model=OrganizationCreateResponse,
             status_code=status.HTTP_201_CREATED,
             responses={
                 400: {"model": OrganizationCreateError, "description": "Bad Request - Invalid input data"},
                 409: {"model": OrganizationCreateError, "description": "Conflict - Duplicate organization or email"},
                 500: {"model": OrganizationCreateError, "description": "Internal Server Error - Database or system error"}
             })
async def create_organization(
    request: OrganizationCreateRequest,
    db: Session = Depends(get_db)
) -> OrganizationCreateResponse:
    """
    Create a new organization with admin user and dynamic database.
    
    Creates:
    - Organization record in master database
    - Dynamic database for the organization
    - Admin user in both master and dynamic databases
    
    Args:
        request: Organization creation request with email, password, and organization name
        db: Database session dependency
        
    Returns:
        OrganizationCreateResponse with success message and organization details
        
    Raises:
        HTTPException: Various HTTP errors based on failure type
    """
    try:
        logger.info(f"Starting organization creation for: {request.organization_name}")
        
        # Create organization with admin users in both databases
        success, message, organization, error_type = OrganizationService.create_organization_with_admin_users(
            db, request
        )
        
        if not success:
            logger.error(f"Organization creation failed: {message}, error_type: {error_type}")
            
            # Map error types to appropriate HTTP status codes
            if error_type == "duplicate_organization":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "error": "Duplicate Organization",
                        "message": message,
                        "error_type": error_type
                    }
                )
            elif error_type == "duplicate_email":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "error": "Duplicate Email",
                        "message": message,
                        "error_type": error_type
                    }
                )
            elif error_type == "database_creation_error":
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail={
                        "error": "Database Creation Failed",
                        "message": message,
                        "error_type": error_type
                    }
                )
            elif error_type == "connection_error":
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail={
                        "error": "Database Connection Failed",
                        "message": message,
                        "error_type": error_type
                    }
                )
            elif error_type == "organization_creation_error":
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail={
                        "error": "Organization Creation Failed",
                        "message": message,
                        "error_type": error_type
                    }
                )
            elif error_type == "admin_creation_error":
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail={
                        "error": "Admin User Creation Failed",
                        "message": message,
                        "error_type": error_type
                    }
                )
            elif error_type == "storage_error":
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail={
                        "error": "Connection Storage Failed",
                        "message": message,
                        "error_type": error_type
                    }
                )
            else:
                # Generic error handling
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail={
                        "error": "Organization Creation Failed",
                        "message": message,
                        "error_type": error_type or "unknown_error"
                    }
                )
        
        logger.info(f"Organization created successfully: {organization.name} (ID: {organization.id})")
        
        # Return success response
        return OrganizationCreateResponse(
            success=True,
            message=message,
            organization_id=organization.id,
            organization_name=organization.name,
            admin_email=organization.admin_email
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions (already handled above)
        raise
        
    except IntegrityError as e:
        # Database integrity constraint violations
        logger.error(f"Database integrity error during organization creation: {str(e)}")
        db.rollback()
        
        error_message = "Database constraint violation"
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            if "name" in str(e).lower():
                error_message = "Organization name already exists"
            elif "email" in str(e).lower():
                error_message = "Admin email already exists"
            
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "Duplicate Data",
                    "message": error_message,
                    "error_type": "integrity_error"
                }
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "Database Error",
                    "message": error_message,
                    "error_type": "integrity_error"
                }
            )
    
    except OperationalError as e:
        # Database connection/operational errors
        logger.error(f"Database operational error during organization creation: {str(e)}")
        db.rollback()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Database Connection Error",
                "message": "Unable to connect to database. Please try again later.",
                "error_type": "operational_error"
            }
        )
    
    except ValueError as e:
        # Input validation errors (should be caught by Pydantic, but just in case)
        logger.error(f"Validation error during organization creation: {str(e)}")
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Invalid Input",
                "message": str(e),
                "error_type": "validation_error"
            }
        )
    
    except Exception as e:
        # Catch-all for unexpected errors
        logger.error(f"Unexpected error during organization creation: {str(e)}")
        db.rollback()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Internal Server Error",
                "message": "An unexpected error occurred. Please try again later.",
                "error_type": "unexpected_error"
            }
        )


@router.get("/get", 
            response_model=OrganizationResponse,
            status_code=status.HTTP_200_OK,
            responses={
                400: {"model": OrganizationError, "description": "Bad Request - Invalid parameters"},
                404: {"model": OrganizationError, "description": "Not Found - Organization does not exist"},
                500: {"model": OrganizationError, "description": "Internal Server Error - Database or system error"}
            })
async def get_organization(
    organization_name: str,
    db: Session = Depends(get_db)
) -> OrganizationResponse:
    """
    Retrieve organization information by organization name.
    
    Returns organization details including ID, name, admin email, and creation timestamp.
    Sensitive information like password hashes and database connection strings are excluded.
    
    Args:
        organization_name: Name of the organization to retrieve
        db: Database session dependency
        
    Returns:
        OrganizationResponse with organization details
        
    Raises:
        HTTPException: Various HTTP errors based on failure type
    """
    try:
        logger.info(f"Retrieving organization information for: {organization_name}")
        
        # Validate input
        if not organization_name or not organization_name.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "success": False,
                    "message": "Organization name is required",
                    "error_type": "validation_error"
                }
            )
        
        # Get organization from database
        organization = OrganizationService.get_organization_by_name(db, organization_name.strip())
        
        if not organization:
            logger.warning(f"Organization not found: {organization_name}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "success": False,
                    "message": f"Organization '{organization_name}' not found",
                    "error_type": "not_found"
                }
            )
        
        logger.info(f"Organization retrieved successfully: {organization.name} (ID: {organization.id})")
        
        # Return organization information (excluding sensitive data)
        return OrganizationResponse(
            success=True,
            organization_id=organization.id,
            organization_name=organization.name,
            admin_email=organization.admin_email,
            created_at=organization.created_at.isoformat() if organization.created_at else None
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
        
    except Exception as e:
        # Handle unexpected errors
        logger.error(f"Unexpected error during organization retrieval: {str(e)}")
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "message": "An unexpected error occurred while retrieving organization information",
                "error_type": "server_error"
            }
        )


@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Health check endpoint for organization service.
    
    Returns:
        Dict with service status
    """
    return {
        "status": "healthy",
        "service": "organization",
        "timestamp": "2025-05-30T07:52:00Z"
    } 