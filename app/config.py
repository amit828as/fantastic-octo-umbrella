from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Application settings
    app_name: str = "Organization Management API"
    debug: bool = False
    
    # Database settings
    database_url: str = Field(
        default="sqlite:///./fastapi_org.db", 
        env="DATABASE_URL"
    )
    test_database_url: Optional[str] = Field(None, env="TEST_DATABASE_URL")
    
    # JWT settings
    jwt_secret_key: str = Field(
        default="dev-secret-key-change-in-production-minimum-32-chars", 
        env="JWT_SECRET_KEY"
    )
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    jwt_access_token_expire_minutes: int = Field(default=30, env="JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    
    # API settings
    api_v1_str: str = Field(default="/api/v1", env="API_V1_STR")
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"


# Global settings instance
settings = Settings() 