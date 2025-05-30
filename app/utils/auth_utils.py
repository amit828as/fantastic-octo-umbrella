from datetime import datetime, timedelta, UTC
from typing import Optional, Dict, Any
import os
from jose import JWTError, jwt
from fastapi import HTTPException, status
import logging

# Configure logging
logger = logging.getLogger(__name__)

class AuthUtils:
    """Utility class for JWT authentication operations"""
    
    # JWT Configuration
    SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    
    @classmethod
    def generate_token(
        cls, 
        user_data: Dict[str, Any], 
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Generate a JWT token with user data.
        
        Args:
            user_data: Dictionary containing user information to encode in token
            expires_delta: Optional custom expiration time
            
        Returns:
            Encoded JWT token string
        """
        try:
            # Prepare the token payload
            to_encode = user_data.copy()
            
            # Set expiration time
            if expires_delta:
                expire = datetime.now(UTC) + expires_delta
            else:
                expire = datetime.now(UTC) + timedelta(minutes=cls.ACCESS_TOKEN_EXPIRE_MINUTES)
            
            # Add standard JWT claims
            to_encode.update({
                "exp": expire,
                "iat": datetime.now(UTC),
                "sub": str(user_data.get("user_id", user_data.get("admin_id", "unknown")))
            })
            
            # Generate and return the token
            encoded_jwt = jwt.encode(to_encode, cls.SECRET_KEY, algorithm=cls.ALGORITHM)
            logger.info(f"Token generated for user: {to_encode.get('sub')}")
            
            return encoded_jwt
            
        except Exception as e:
            logger.error(f"Error generating token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not generate authentication token"
            )
    
    @classmethod
    def verify_token(cls, token: str) -> Dict[str, Any]:
        """
        Verify and decode a JWT token.
        
        Args:
            token: JWT token string to verify
            
        Returns:
            Decoded token payload
            
        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            # Decode and verify the token
            payload = jwt.decode(token, cls.SECRET_KEY, algorithms=[cls.ALGORITHM])
            
            # Check if token has expired
            exp_timestamp = payload.get("exp")
            if exp_timestamp is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token missing expiration claim"
                )
            
            # Verify expiration (jwt.decode already checks this, but explicit check for clarity)
            if datetime.fromtimestamp(exp_timestamp, UTC) < datetime.now(UTC):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired"
                )
            
            logger.info(f"Token verified for user: {payload.get('sub')}")
            return payload
            
        except JWTError as e:
            logger.warning(f"JWT verification failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except HTTPException:
            # Re-raise HTTP exceptions as-is
            raise
        except Exception as e:
            logger.error(f"Unexpected error during token verification: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication error"
            )
    
    @classmethod
    def get_current_user(cls, token: str) -> Dict[str, Any]:
        """
        Extract current user information from a valid JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            Dictionary containing user information
            
        Raises:
            HTTPException: If token is invalid or user data is incomplete
        """
        try:
            # Verify the token and get payload
            payload = cls.verify_token(token)
            
            # Extract user identification
            user_id = payload.get("sub")
            if user_id is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token missing user identification"
                )
            
            # Extract user information
            user_info = {
                "user_id": user_id,
                "admin_id": payload.get("admin_id"),
                "organization_id": payload.get("organization_id"),
                "email": payload.get("email"),
                "organization_name": payload.get("organization_name"),
                "token_issued_at": payload.get("iat"),
                "token_expires_at": payload.get("exp")
            }
            
            # Remove None values
            user_info = {k: v for k, v in user_info.items() if v is not None}
            
            logger.info(f"Current user extracted: {user_id}")
            return user_info
            
        except HTTPException:
            # Re-raise HTTP exceptions as-is
            raise
        except Exception as e:
            logger.error(f"Error extracting user from token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not extract user information"
            )
    
    @classmethod
    def create_admin_token_data(
        cls, 
        admin_id: int, 
        email: str, 
        organization_id: int,
        organization_name: str
    ) -> Dict[str, Any]:
        """
        Create token data dictionary for admin users.
        
        Args:
            admin_id: Admin user ID
            email: Admin email
            organization_id: Organization ID
            organization_name: Organization name
            
        Returns:
            Dictionary ready for token generation
        """
        return {
            "admin_id": admin_id,
            "user_id": admin_id,  # For compatibility with generic user functions
            "email": email,
            "organization_id": organization_id,
            "organization_name": organization_name,
            "user_type": "admin"
        }
    
    @classmethod
    def extract_bearer_token(cls, authorization: str) -> str:
        """
        Extract bearer token from Authorization header.
        
        Args:
            authorization: Authorization header value
            
        Returns:
            JWT token string
            
        Raises:
            HTTPException: If authorization format is invalid
        """
        try:
            # Check if authorization header exists
            if not authorization:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authorization header missing",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Check if it starts with "Bearer "
            if not authorization.startswith("Bearer "):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authorization header format. Expected 'Bearer <token>'",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Extract the token
            token = authorization.split(" ")[1]
            if not token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token missing from authorization header",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            return token
            
        except HTTPException:
            # Re-raise HTTP exceptions as-is
            raise
        except Exception as e:
            logger.error(f"Error extracting bearer token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            ) 