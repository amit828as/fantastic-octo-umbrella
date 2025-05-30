import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, OperationalError

from app.main import app
from app.schemas.organization import OrganizationCreateRequest
from app.models.organization import Organization

client = TestClient(app)


class TestOrganizationEndpoint:
    """Test the organization creation endpoint"""
    
    @patch('app.routers.organization.get_db')
    @patch('app.services.organization_service.OrganizationService.create_organization_with_admin_users')
    def test_create_organization_success(self, mock_create_org, mock_get_db):
        """Test successful organization creation"""
        # Setup
        mock_db = Mock(spec=Session)
        mock_get_db.return_value = mock_db
        
        organization = Organization(
            id=1,
            name="Test Corp",
            admin_email="admin@test.com",
            admin_password_hash="hashed_password",
            dynamic_db_connection_string="sqlite:///test_dynamic.db"
        )
        
        mock_create_org.return_value = (True, "Organization created successfully", organization, None)
        
        # Execute
        response = client.post(
            "/api/v1/org/create",
            json={
                "email": "admin@test.com",
                "password": "SecurePassword123!",
                "organization_name": "Test Corp"
            }
        )
        
        # Verify
        assert response.status_code == 201
        data = response.json()
        assert data["success"] == True
        assert data["message"] == "Organization created successfully"
        assert data["organization_id"] == 1
        assert data["organization_name"] == "Test Corp"
        assert data["admin_email"] == "admin@test.com"
    
    @patch('app.routers.organization.get_db')
    @patch('app.services.organization_service.OrganizationService.create_organization_with_admin_users')
    def test_create_organization_duplicate_organization(self, mock_create_org, mock_get_db):
        """Test organization creation with duplicate organization name"""
        # Setup
        mock_db = Mock(spec=Session)
        mock_get_db.return_value = mock_db
        
        mock_create_org.return_value = (False, "Organization name 'Test Corp' already exists", None, "duplicate_organization")
        
        # Execute
        response = client.post(
            "/api/v1/org/create",
            json={
                "email": "admin@test.com",
                "password": "SecurePassword123!",
                "organization_name": "Test Corp"
            }
        )
        
        # Verify
        assert response.status_code == 409
        data = response.json()
        assert data["detail"]["error"] == "Duplicate Organization"
        assert data["detail"]["error_type"] == "duplicate_organization"
    
    @patch('app.routers.organization.get_db')
    @patch('app.services.organization_service.OrganizationService.create_organization_with_admin_users')
    def test_create_organization_duplicate_email(self, mock_create_org, mock_get_db):
        """Test organization creation with duplicate admin email"""
        # Setup
        mock_db = Mock(spec=Session)
        mock_get_db.return_value = mock_db
        
        mock_create_org.return_value = (False, "Admin email 'admin@test.com' already exists", None, "duplicate_email")
        
        # Execute
        response = client.post(
            "/api/v1/org/create",
            json={
                "email": "admin@test.com",
                "password": "SecurePassword123!",
                "organization_name": "New Corp"
            }
        )
        
        # Verify
        assert response.status_code == 409
        data = response.json()
        assert data["detail"]["error"] == "Duplicate Email"
        assert data["detail"]["error_type"] == "duplicate_email"
    
    @patch('app.routers.organization.get_db')
    @patch('app.services.organization_service.OrganizationService.create_organization_with_admin_users')
    def test_create_organization_database_error(self, mock_create_org, mock_get_db):
        """Test organization creation with database creation error"""
        # Setup
        mock_db = Mock(spec=Session)
        mock_get_db.return_value = mock_db
        
        mock_create_org.return_value = (False, "Failed to create dynamic database", None, "database_creation_error")
        
        # Execute
        response = client.post(
            "/api/v1/org/create",
            json={
                "email": "admin@test.com",
                "password": "SecurePassword123!",
                "organization_name": "Test Corp"
            }
        )
        
        # Verify
        assert response.status_code == 500
        data = response.json()
        assert data["detail"]["error"] == "Database Creation Failed"
        assert data["detail"]["error_type"] == "database_creation_error"
    
    @patch('app.routers.organization.get_db')
    @patch('app.services.organization_service.OrganizationService.create_organization_with_admin_users')
    def test_create_organization_admin_creation_error(self, mock_create_org, mock_get_db):
        """Test organization creation with admin creation error"""
        # Setup
        mock_db = Mock(spec=Session)
        mock_get_db.return_value = mock_db
        
        mock_create_org.return_value = (False, "Failed to create admin users", None, "admin_creation_error")
        
        # Execute
        response = client.post(
            "/api/v1/org/create",
            json={
                "email": "admin@test.com",
                "password": "SecurePassword123!",
                "organization_name": "Test Corp"
            }
        )
        
        # Verify
        assert response.status_code == 500
        data = response.json()
        assert data["detail"]["error"] == "Admin User Creation Failed"
        assert data["detail"]["error_type"] == "admin_creation_error"
    
    def test_create_organization_invalid_email(self):
        """Test organization creation with invalid email format"""
        response = client.post(
            "/api/v1/org/create",
            json={
                "email": "invalid-email",
                "password": "SecurePassword123!",
                "organization_name": "Test Corp"
            }
        )
        
        # Verify
        assert response.status_code == 422  # Pydantic validation error
        data = response.json()
        assert "detail" in data
    
    def test_create_organization_weak_password(self):
        """Test organization creation with weak password"""
        response = client.post(
            "/api/v1/org/create",
            json={
                "email": "admin@test.com",
                "password": "weak",
                "organization_name": "Test Corp"
            }
        )
        
        # Verify
        assert response.status_code == 422  # Pydantic validation error
        data = response.json()
        assert "detail" in data
    
    def test_create_organization_invalid_organization_name(self):
        """Test organization creation with invalid organization name"""
        response = client.post(
            "/api/v1/org/create",
            json={
                "email": "admin@test.com",
                "password": "SecurePassword123!",
                "organization_name": ""  # Empty name
            }
        )
        
        # Verify
        assert response.status_code == 422  # Pydantic validation error
        data = response.json()
        assert "detail" in data
    
    @patch('app.routers.organization.get_db')
    def test_create_organization_integrity_error(self, mock_get_db):
        """Test organization creation with SQLAlchemy IntegrityError"""
        # Setup
        mock_db = Mock(spec=Session)
        mock_get_db.return_value = mock_db
        
        # Mock IntegrityError
        with patch('app.services.organization_service.OrganizationService.create_organization_with_admin_users') as mock_create:
            mock_create.side_effect = IntegrityError("UNIQUE constraint failed: organizations.name", {}, None)
            
            # Execute
            response = client.post(
                "/api/v1/org/create",
                json={
                    "email": "admin@test.com",
                    "password": "SecurePassword123!",
                    "organization_name": "Test Corp"
                }
            )
            
            # Verify
            assert response.status_code == 409
            data = response.json()
            assert data["detail"]["error"] == "Duplicate Data"
            assert data["detail"]["error_type"] == "integrity_error"
    
    @patch('app.routers.organization.get_db')
    def test_create_organization_operational_error(self, mock_get_db):
        """Test organization creation with SQLAlchemy OperationalError"""
        # Setup
        mock_db = Mock(spec=Session)
        mock_get_db.return_value = mock_db
        
        # Mock OperationalError
        with patch('app.services.organization_service.OrganizationService.create_organization_with_admin_users') as mock_create:
            mock_create.side_effect = OperationalError("Database connection failed", {}, None)
            
            # Execute
            response = client.post(
                "/api/v1/org/create",
                json={
                    "email": "admin@test.com",
                    "password": "SecurePassword123!",
                    "organization_name": "Test Corp"
                }
            )
            
            # Verify
            assert response.status_code == 500
            data = response.json()
            assert data["detail"]["error"] == "Database Connection Error"
            assert data["detail"]["error_type"] == "operational_error"
    
    @patch('app.routers.organization.get_db')
    def test_create_organization_unexpected_error(self, mock_get_db):
        """Test organization creation with unexpected error"""
        # Setup
        mock_db = Mock(spec=Session)
        mock_get_db.return_value = mock_db
        
        # Mock unexpected error
        with patch('app.services.organization_service.OrganizationService.create_organization_with_admin_users') as mock_create:
            mock_create.side_effect = Exception("Unexpected error")
            
            # Execute
            response = client.post(
                "/api/v1/org/create",
                json={
                    "email": "admin@test.com",
                    "password": "SecurePassword123!",
                    "organization_name": "Test Corp"
                }
            )
            
            # Verify
            assert response.status_code == 500
            data = response.json()
            assert data["detail"]["error"] == "Internal Server Error"
            assert data["detail"]["error_type"] == "unexpected_error"
    
    def test_organization_health_endpoint(self):
        """Test the organization health endpoint"""
        response = client.get("/api/v1/org/health")
        
        # Verify
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "organization"
    
    def test_root_endpoint(self):
        """Test the root endpoint"""
        response = client.get("/")
        
        # Verify
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "running"
        assert data["message"] == "Organization Management API"
    
    def test_main_health_endpoint(self):
        """Test the main health endpoint"""
        response = client.get("/health")
        
        # Verify
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy" 