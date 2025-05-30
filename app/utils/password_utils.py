from passlib.context import CryptContext
from typing import Optional


class PasswordUtils:
    """Utility class for password hashing and verification operations"""
    
    # Configure passlib CryptContext with bcrypt
    _pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    @classmethod
    def hash_password(cls, password: str) -> str:
        """
        Hash a password using bcrypt.
        
        Args:
            password: Plain text password to hash
            
        Returns:
            Hashed password string
        """
        return cls._pwd_context.hash(password)
    
    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            plain_password: Plain text password to verify
            hashed_password: Hashed password to verify against
            
        Returns:
            True if password matches, False otherwise
        """
        return cls._pwd_context.verify(plain_password, hashed_password)
    
    @classmethod
    def needs_update(cls, hashed_password: str) -> bool:
        """
        Check if a hashed password needs to be rehashed (due to updated settings).
        
        Args:
            hashed_password: The hashed password to check
            
        Returns:
            True if the hash needs updating, False otherwise
        """
        return cls._pwd_context.needs_update(hashed_password)
    
    @classmethod
    def get_hash_info(cls, hashed_password: str) -> Optional[dict]:
        """
        Get information about a hashed password.
        
        Args:
            hashed_password: The hashed password to analyze
            
        Returns:
            Dictionary with hash information or None if invalid
        """
        try:
            return cls._pwd_context.hash_info(hashed_password)
        except Exception:
            return None 