import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timedelta, UTC
from jose import jwt

from app.main import app
from app.utils.auth_utils import AuthUtils

client = TestClient(app)


class TestAuthErrorHandling:
    """Test authentication error handling scenarios"""
    
    def test_missing_authorization_header(self):
        """Test accessing protected endpoint without authorization header"""
        response = client.get("/api/v1/auth/me")
        
        assert response.status_code == 422
        assert "authorization" in response.json()["detail"][0]["loc"]
        assert response.json()["detail"][0]["msg"] == "Field required"
    
    def test_invalid_authorization_format(self):
        """Test accessing protected endpoint with invalid authorization format"""
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "InvalidFormat"}
        )
        
        assert response.status_code == 401
        assert "Invalid authorization header format" in response.json()["detail"]
    
    def test_missing_bearer_prefix(self):
        """Test accessing protected endpoint without Bearer prefix"""
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "token-without-bearer"}
        )
        
        assert response.status_code == 401
        assert "Invalid authorization header format" in response.json()["detail"]
    
    def test_empty_token(self):
        """Test accessing protected endpoint with empty token"""
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer "}
        )
        
        assert response.status_code == 401
        assert "Token missing from authorization header" in response.json()["detail"]
    
    def test_invalid_token_format(self):
        """Test accessing protected endpoint with invalid token format"""
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid-token-format"}
        )
        
        assert response.status_code == 401
        assert "Could not validate credentials" in response.json()["detail"]
    
    def test_expired_token(self):
        """Test accessing protected endpoint with expired token"""
        # Create an expired token
        expired_time = datetime.now(UTC) - timedelta(hours=1)
        token_data = {
            "admin_id": 1,
            "email": "test@example.com",
            "organization_id": 1,
            "exp": expired_time,
            "iat": datetime.now(UTC) - timedelta(hours=2),
            "sub": "1"
        }
        
        expired_token = jwt.encode(
            token_data, 
            AuthUtils.SECRET_KEY, 
            algorithm=AuthUtils.ALGORITHM
        )
        
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        
        assert response.status_code == 401
        assert "Could not validate credentials" in response.json()["detail"]
    
    def test_token_with_invalid_signature(self):
        """Test accessing protected endpoint with token having invalid signature"""
        # Create a token with wrong secret
        token_data = {
            "admin_id": 1,
            "email": "test@example.com",
            "organization_id": 1,
            "exp": datetime.now(UTC) + timedelta(hours=1),
            "iat": datetime.now(UTC),
            "sub": "1"
        }
        
        invalid_token = jwt.encode(
            token_data, 
            "wrong-secret-key",  # Wrong secret
            algorithm=AuthUtils.ALGORITHM
        )
        
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {invalid_token}"}
        )
        
        assert response.status_code == 401
        assert "Could not validate credentials" in response.json()["detail"]
    
    def test_token_missing_required_claims(self):
        """Test accessing protected endpoint with token missing required claims"""
        # Create a token without required claims
        token_data = {
            "some_field": "some_value",
            "exp": datetime.now(UTC) + timedelta(hours=1),
            "iat": datetime.now(UTC)
            # Missing 'sub' claim
        }
        
        invalid_token = jwt.encode(
            token_data, 
            AuthUtils.SECRET_KEY, 
            algorithm=AuthUtils.ALGORITHM
        )
        
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {invalid_token}"}
        )
        
        assert response.status_code == 401
        assert "Could not validate credentials" in response.json()["detail"]
    
    def test_login_with_invalid_credentials(self):
        """Test login with invalid email/password"""
        response = client.post(
            "/api/v1/auth/admin/login",
            json={
                "email": "nonexistent@example.com",
                "password": "wrongpassword"
            }
        )
        
        assert response.status_code == 401
        assert response.json()["detail"]["error"] == "Authentication Failed"
        assert "Invalid email or password" in response.json()["detail"]["message"]
        assert response.json()["detail"]["error_type"] == "authentication_error"
    
    def test_login_with_invalid_email_format(self):
        """Test login with invalid email format"""
        response = client.post(
            "/api/v1/auth/admin/login",
            json={
                "email": "invalid-email-format",
                "password": "somepassword"
            }
        )
        
        assert response.status_code == 422
        assert "value is not a valid email address" in str(response.json())
    
    def test_login_with_short_password(self):
        """Test login with password too short"""
        response = client.post(
            "/api/v1/auth/admin/login",
            json={
                "email": "test@example.com",
                "password": "short"  # Less than 8 characters
            }
        )
        
        assert response.status_code == 422
        assert "at least 8 characters" in str(response.json())
    
    def test_token_validation_with_invalid_token(self):
        """Test token validation endpoint with invalid token"""
        response = client.post(
            "/api/v1/auth/validate-token",
            headers={"Authorization": "Bearer invalid-token"}
        )
        
        assert response.status_code == 200
        assert response.json()["valid"] == False
        assert response.json()["user_id"] is None
    
    def test_token_refresh_with_invalid_token(self):
        """Test token refresh endpoint with invalid token"""
        response = client.post(
            "/api/v1/auth/refresh-token",
            headers={"Authorization": "Bearer invalid-token"}
        )
        
        assert response.status_code == 401
        assert "Token Refresh Failed" in response.json()["detail"]["error"] 