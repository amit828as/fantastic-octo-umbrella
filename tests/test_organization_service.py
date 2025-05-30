import pytest
from unittest.mock import Mock, patch
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.services.organization_service import OrganizationService
from app.models.organization import Organization
from app.models.admin import Admin
from app.schemas.organization import OrganizationCreateRequest


class TestOrganizationService:
    """Test OrganizationService methods"""
    
    def test_check_organization_name_exists_true(self):
        """Test organization name exists check returns True when organization exists"""
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_query = Mock()
        mock_filter = Mock()
        mock_organization = Organization(
            name="Test Corp",
            admin_email="admin@test.com",
            admin_password_hash="hashed",
            dynamic_db_connection_string="connection"
        )
        
        # Set up mock chain
        mock_filter.first.return_value = mock_organization
        mock_query.filter.return_value = mock_filter
        mock_db.query.return_value = mock_query
        
        # Test
        result = OrganizationService.check_organization_name_exists(mock_db, "Test Corp")
        
        assert result is True
        mock_db.query.assert_called_once_with(Organization)
    
    def test_check_organization_name_exists_false(self):
        """Test organization name exists check returns False when organization doesn't exist"""
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_query = Mock()
        mock_filter = Mock()
        
        # Set up mock chain
        mock_filter.first.return_value = None
        mock_query.filter.return_value = mock_filter
        mock_db.query.return_value = mock_query
        
        # Test
        result = OrganizationService.check_organization_name_exists(mock_db, "Nonexistent Corp")
        
        assert result is False
        mock_db.query.assert_called_once_with(Organization)
    
    def test_check_organization_name_case_insensitive(self):
        """Test organization name check is case insensitive"""
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_query = Mock()
        mock_filter = Mock()
        mock_organization = Organization(
            name="Test Corp",
            admin_email="admin@test.com",
            admin_password_hash="hashed",
            dynamic_db_connection_string="connection"
        )
        
        # Set up mock chain
        mock_filter.first.return_value = mock_organization
        mock_query.filter.return_value = mock_filter
        mock_db.query.return_value = mock_query
        
        # Test with different case
        result = OrganizationService.check_organization_name_exists(mock_db, "TEST CORP")
        
        assert result is True
    
    def test_check_admin_email_exists_true(self):
        """Test admin email exists check returns True when email exists"""
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_query = Mock()
        mock_filter = Mock()
        mock_admin = Admin(email="admin@test.com", password_hash="hashed", organization_id=1)
        
        # Set up mock chain
        mock_filter.first.return_value = mock_admin
        mock_query.filter.return_value = mock_filter
        mock_db.query.return_value = mock_query
        
        # Test
        result = OrganizationService.check_admin_email_exists(mock_db, "admin@test.com")
        
        assert result is True
        mock_db.query.assert_called_once_with(Admin)
    
    def test_check_admin_email_exists_false(self):
        """Test admin email exists check returns False when email doesn't exist"""
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_query = Mock()
        mock_filter = Mock()
        
        # Set up mock chain
        mock_filter.first.return_value = None
        mock_query.filter.return_value = mock_filter
        mock_db.query.return_value = mock_query
        
        # Test
        result = OrganizationService.check_admin_email_exists(mock_db, "nonexistent@test.com")
        
        assert result is False
        mock_db.query.assert_called_once_with(Admin)
    
    def test_check_admin_email_case_insensitive(self):
        """Test admin email check is case insensitive"""
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_query = Mock()
        mock_filter = Mock()
        mock_admin = Admin(email="admin@test.com", password_hash="hashed", organization_id=1)
        
        # Set up mock chain
        mock_filter.first.return_value = mock_admin
        mock_query.filter.return_value = mock_filter
        mock_db.query.return_value = mock_query
        
        # Test with different case
        result = OrganizationService.check_admin_email_exists(mock_db, "ADMIN@TEST.COM")
        
        assert result is True
    
    @patch.object(OrganizationService, 'check_organization_name_exists')
    @patch.object(OrganizationService, 'check_admin_email_exists')
    def test_validate_organization_creation_request_success(self, mock_check_email, mock_check_org):
        """Test successful validation of organization creation request"""
        # Mock return values
        mock_check_org.return_value = False  # Organization doesn't exist
        mock_check_email.return_value = False  # Email doesn't exist
        
        # Create request
        request = OrganizationCreateRequest(
            email="admin@test.com",
            password="SecurePassword123!",
            organization_name="Test Corp"
        )
        
        mock_db = Mock(spec=Session)
        
        # Test
        is_valid, message, error_type = OrganizationService.validate_organization_creation_request(
            mock_db, request
        )
        
        assert is_valid is True
        assert message == "Validation passed"
        assert error_type is None
    
    @patch.object(OrganizationService, 'check_organization_name_exists')
    @patch.object(OrganizationService, 'check_admin_email_exists')
    def test_validate_organization_creation_request_duplicate_org(self, mock_check_email, mock_check_org):
        """Test validation failure due to duplicate organization name"""
        # Mock return values
        mock_check_org.return_value = True  # Organization exists
        mock_check_email.return_value = False  # Email doesn't exist
        
        # Create request
        request = OrganizationCreateRequest(
            email="admin@test.com",
            password="SecurePassword123!",
            organization_name="Test Corp"
        )
        
        mock_db = Mock(spec=Session)
        
        # Test
        is_valid, message, error_type = OrganizationService.validate_organization_creation_request(
            mock_db, request
        )
        
        assert is_valid is False
        assert "Test Corp" in message
        assert "already exists" in message
        assert error_type == "duplicate_organization"
    
    @patch.object(OrganizationService, 'check_organization_name_exists')
    @patch.object(OrganizationService, 'check_admin_email_exists')
    def test_validate_organization_creation_request_duplicate_email(self, mock_check_email, mock_check_org):
        """Test validation failure due to duplicate admin email"""
        # Mock return values
        mock_check_org.return_value = False  # Organization doesn't exist
        mock_check_email.return_value = True  # Email exists
        
        # Create request
        request = OrganizationCreateRequest(
            email="admin@test.com",
            password="SecurePassword123!",
            organization_name="Test Corp"
        )
        
        mock_db = Mock(spec=Session)
        
        # Test
        is_valid, message, error_type = OrganizationService.validate_organization_creation_request(
            mock_db, request
        )
        
        assert is_valid is False
        assert "admin@test.com" in message
        assert "already exists" in message
        assert error_type == "duplicate_email"
    
    @patch.object(OrganizationService, 'check_organization_name_exists')
    @patch.object(OrganizationService, 'check_admin_email_exists')
    def test_create_organization_atomic_success(self, mock_check_email, mock_check_org):
        """Test successful atomic organization creation"""
        # Mock return values
        mock_check_org.return_value = False  # Organization doesn't exist
        mock_check_email.return_value = False  # Email doesn't exist
        
        # Mock database session
        mock_db = Mock(spec=Session)
        
        # Test
        success, message, organization = OrganizationService.create_organization_atomic(
            mock_db, "Test Corp", "admin@test.com", "hashed_password", "connection_string"
        )
        
        assert success is True
        assert message == "Organization created successfully"
        assert organization is not None
        assert organization.name == "Test Corp"
        assert organization.admin_email == "admin@test.com"
        assert organization.admin_password_hash == "hashed_password"
        assert organization.dynamic_db_connection_string == "connection_string"
        
        mock_db.add.assert_called_once()
        mock_db.flush.assert_called_once()
    
    @patch.object(OrganizationService, 'check_organization_name_exists')
    @patch.object(OrganizationService, 'check_admin_email_exists')
    def test_create_organization_atomic_duplicate_org_check(self, mock_check_email, mock_check_org):
        """Test atomic organization creation with duplicate organization check during transaction"""
        # Mock return values - organization exists during transaction
        mock_check_org.return_value = True
        mock_check_email.return_value = False
        
        # Mock database session
        mock_db = Mock(spec=Session)
        
        # Test
        success, message, organization = OrganizationService.create_organization_atomic(
            mock_db, "Test Corp", "admin@test.com", "hashed_password", "connection_string"
        )
        
        assert success is False
        assert "Test Corp" in message
        assert "already exists" in message
        assert organization is None
        
        # Should not attempt to add to database
        mock_db.add.assert_not_called()
    
    @patch.object(OrganizationService, 'check_organization_name_exists')
    @patch.object(OrganizationService, 'check_admin_email_exists')
    def test_create_organization_atomic_duplicate_email_check(self, mock_check_email, mock_check_org):
        """Test atomic organization creation with duplicate email check during transaction"""
        # Mock return values - email exists during transaction
        mock_check_org.return_value = False
        mock_check_email.return_value = True
        
        # Mock database session
        mock_db = Mock(spec=Session)
        
        # Test
        success, message, organization = OrganizationService.create_organization_atomic(
            mock_db, "Test Corp", "admin@test.com", "hashed_password", "connection_string"
        )
        
        assert success is False
        assert "admin@test.com" in message
        assert "already exists" in message
        assert organization is None
        
        # Should not attempt to add to database
        mock_db.add.assert_not_called()
    
    @patch.object(OrganizationService, 'check_organization_name_exists')
    @patch.object(OrganizationService, 'check_admin_email_exists')
    def test_create_organization_atomic_integrity_error(self, mock_check_email, mock_check_org):
        """Test atomic organization creation with integrity error"""
        # Mock return values
        mock_check_org.return_value = False
        mock_check_email.return_value = False
        
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_db.add.side_effect = IntegrityError("duplicate key name", None, None)
        
        # Test
        success, message, organization = OrganizationService.create_organization_atomic(
            mock_db, "Test Corp", "admin@test.com", "hashed_password", "connection_string"
        )
        
        assert success is False
        assert "Test Corp" in message
        assert "already exists" in message
        assert organization is None
        
        mock_db.rollback.assert_called_once()
    
    @patch.object(OrganizationService, 'check_organization_name_exists')
    @patch.object(OrganizationService, 'check_admin_email_exists')
    def test_create_organization_atomic_general_error(self, mock_check_email, mock_check_org):
        """Test atomic organization creation with general error"""
        # Mock return values
        mock_check_org.return_value = False
        mock_check_email.return_value = False
        
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_db.add.side_effect = Exception("Database connection failed")
        
        # Test
        success, message, organization = OrganizationService.create_organization_atomic(
            mock_db, "Test Corp", "admin@test.com", "hashed_password", "connection_string"
        )
        
        assert success is False
        assert "Failed to create organization" in message
        assert "Database connection failed" in message
        assert organization is None
        
        mock_db.rollback.assert_called_once()
    
    @patch('app.services.organization_service.DatabaseManager')
    @patch.object(OrganizationService, 'validate_organization_creation_request')
    @patch.object(OrganizationService, 'create_organization_atomic')
    def test_create_organization_with_dynamic_database_success(self, mock_create_org, mock_validate, mock_db_manager_class):
        """Test successful complete organization creation workflow"""
        # Mock validation
        mock_validate.return_value = (True, "Validation passed", None)
        
        # Mock DatabaseManager
        mock_db_manager = Mock()
        mock_db_manager_class.return_value = mock_db_manager
        mock_db_manager.generate_database_name.return_value = "test_corp_20240101_abc123"
        mock_db_manager.create_and_migrate_database.return_value = (True, "Database created")
        mock_db_manager.get_connection_info.return_value = "sqlite:///test_corp_20240101_abc123.db"
        mock_db_manager.store_connection_info.return_value = (True, "Connection stored")
        
        # Mock organization creation
        mock_organization = Organization(
            id=1,
            name="Test Corp",
            admin_email="admin@test.com",
            admin_password_hash="hashed_password",
            dynamic_db_connection_string="sqlite:///test_corp_20240101_abc123.db"
        )
        mock_create_org.return_value = (True, "Organization created successfully", mock_organization)
        
        # Mock database session
        mock_db = Mock(spec=Session)
        
        # Create request
        request = OrganizationCreateRequest(
            email="admin@test.com",
            password="SecurePassword123!",
            organization_name="Test Corp"
        )
        
        # Test
        success, message, organization, error_type = OrganizationService.create_organization_with_dynamic_database(
            mock_db, request, "hashed_password"
        )
        
        assert success is True
        assert message == "Organization and dynamic database created successfully"
        assert organization is not None
        assert organization.name == "Test Corp"
        assert error_type is None
        
        # Verify all steps were called
        mock_validate.assert_called_once()
        mock_db_manager.generate_database_name.assert_called_once_with("Test Corp")
        mock_db_manager.create_and_migrate_database.assert_called_once_with("test_corp_20240101_abc123")
        mock_db_manager.get_connection_info.assert_called_once_with("test_corp_20240101_abc123")
        mock_create_org.assert_called_once()
        mock_db_manager.store_connection_info.assert_called_once_with(mock_db, 1, "sqlite:///test_corp_20240101_abc123.db")
        mock_db.commit.assert_called_once()
    
    @patch('app.services.organization_service.DatabaseManager')
    @patch.object(OrganizationService, 'validate_organization_creation_request')
    def test_create_organization_with_dynamic_database_validation_failure(self, mock_validate, mock_db_manager_class):
        """Test workflow failure during validation"""
        # Mock validation failure
        mock_validate.return_value = (False, "Organization name already exists", "duplicate_organization")
        
        # Mock database session
        mock_db = Mock(spec=Session)
        
        # Create request
        request = OrganizationCreateRequest(
            email="admin@test.com",
            password="SecurePassword123!",
            organization_name="Test Corp"
        )
        
        # Test
        success, message, organization, error_type = OrganizationService.create_organization_with_dynamic_database(
            mock_db, request, "hashed_password"
        )
        
        assert success is False
        assert message == "Organization name already exists"
        assert organization is None
        assert error_type == "duplicate_organization"
        
        # Verify no database operations were attempted
        mock_db_manager_class.assert_not_called()
    
    @patch('app.services.organization_service.DatabaseManager')
    @patch.object(OrganizationService, 'validate_organization_creation_request')
    def test_create_organization_with_dynamic_database_db_creation_failure(self, mock_validate, mock_db_manager_class):
        """Test workflow failure during database creation"""
        # Mock validation success
        mock_validate.return_value = (True, "Validation passed", None)
        
        # Mock DatabaseManager with database creation failure
        mock_db_manager = Mock()
        mock_db_manager_class.return_value = mock_db_manager
        mock_db_manager.generate_database_name.return_value = "test_corp_20240101_abc123"
        mock_db_manager.create_and_migrate_database.return_value = (False, "Database creation failed")
        
        # Mock database session
        mock_db = Mock(spec=Session)
        
        # Create request
        request = OrganizationCreateRequest(
            email="admin@test.com",
            password="SecurePassword123!",
            organization_name="Test Corp"
        )
        
        # Test
        success, message, organization, error_type = OrganizationService.create_organization_with_dynamic_database(
            mock_db, request, "hashed_password"
        )
        
        assert success is False
        assert "Failed to create dynamic database" in message
        assert "Database creation failed" in message
        assert organization is None
        assert error_type == "database_creation_error"
    
    @patch('app.services.organization_service.DatabaseManager')
    @patch.object(OrganizationService, 'validate_organization_creation_request')
    @patch.object(OrganizationService, 'create_organization_atomic')
    def test_create_organization_with_dynamic_database_org_creation_failure(self, mock_create_org, mock_validate, mock_db_manager_class):
        """Test workflow failure during organization creation with cleanup"""
        # Mock validation success
        mock_validate.return_value = (True, "Validation passed", None)
        
        # Mock DatabaseManager
        mock_db_manager = Mock()
        mock_db_manager_class.return_value = mock_db_manager
        mock_db_manager.generate_database_name.return_value = "test_corp_20240101_abc123"
        mock_db_manager.create_and_migrate_database.return_value = (True, "Database created")
        mock_db_manager.get_connection_info.return_value = "sqlite:///test_corp_20240101_abc123.db"
        
        # Mock organization creation failure
        mock_create_org.return_value = (False, "Organization creation failed", None)
        
        # Mock database session
        mock_db = Mock(spec=Session)
        
        # Create request
        request = OrganizationCreateRequest(
            email="admin@test.com",
            password="SecurePassword123!",
            organization_name="Test Corp"
        )
        
        # Test
        success, message, organization, error_type = OrganizationService.create_organization_with_dynamic_database(
            mock_db, request, "hashed_password"
        )
        
        assert success is False
        assert message == "Organization creation failed"
        assert organization is None
        assert error_type == "organization_creation_error"
        
        # Verify cleanup was attempted
        mock_db_manager.cleanup_database.assert_called_once_with("test_corp_20240101_abc123")
    
    @patch.object(OrganizationService, 'check_admin_email_exists')
    def test_create_admin_user_atomic_success(self, mock_check_exists):
        """Test successful atomic admin user creation"""
        # Mock return value
        mock_check_exists.return_value = False  # Email doesn't exist
        
        # Mock database session
        mock_db = Mock(spec=Session)
        
        # Test
        success, message, admin = OrganizationService.create_admin_user_atomic(
            mock_db, "admin@test.com", "hashed_password", 1
        )
        
        assert success is True
        assert message == "Admin user created successfully"
        assert admin is not None
        assert admin.email == "admin@test.com"
        assert admin.password_hash == "hashed_password"
        assert admin.organization_id == 1
        
        mock_db.add.assert_called_once()
        mock_db.flush.assert_called_once()
    
    @patch.object(OrganizationService, 'check_admin_email_exists')
    def test_create_admin_user_atomic_duplicate_check(self, mock_check_exists):
        """Test atomic admin user creation with duplicate check during transaction"""
        # Mock return value - email exists during transaction
        mock_check_exists.return_value = True
        
        # Mock database session
        mock_db = Mock(spec=Session)
        
        # Test
        success, message, admin = OrganizationService.create_admin_user_atomic(
            mock_db, "admin@test.com", "hashed_password", 1
        )
        
        assert success is False
        assert "admin@test.com" in message
        assert "already exists" in message
        assert admin is None
        
        # Should not attempt to add to database
        mock_db.add.assert_not_called()
    
    @patch.object(OrganizationService, 'check_admin_email_exists')
    def test_create_admin_user_atomic_integrity_error(self, mock_check_exists):
        """Test atomic admin user creation with integrity error"""
        # Mock return value
        mock_check_exists.return_value = False
        
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_db.add.side_effect = IntegrityError("duplicate key", None, None)
        
        # Test
        success, message, admin = OrganizationService.create_admin_user_atomic(
            mock_db, "admin@test.com", "hashed_password", 1
        )
        
        assert success is False
        assert "admin@test.com" in message
        assert "already exists" in message
        assert admin is None
        
        mock_db.rollback.assert_called_once()
    
    def test_get_organization_by_id(self):
        """Test getting organization by ID"""
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_query = Mock()
        mock_filter = Mock()
        mock_organization = Organization(
            id=1,
            name="Test Corp",
            admin_email="admin@test.com",
            admin_password_hash="hashed",
            dynamic_db_connection_string="connection"
        )
        
        # Set up mock chain
        mock_filter.first.return_value = mock_organization
        mock_query.filter.return_value = mock_filter
        mock_db.query.return_value = mock_query
        
        # Test
        result = OrganizationService.get_organization_by_id(mock_db, 1)
        
        assert result == mock_organization
        mock_db.query.assert_called_once_with(Organization)
    
    def test_get_organization_by_name(self):
        """Test getting organization by name"""
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_query = Mock()
        mock_filter = Mock()
        mock_organization = Organization(
            name="Test Corp",
            admin_email="admin@test.com",
            admin_password_hash="hashed",
            dynamic_db_connection_string="connection"
        )
        
        # Set up mock chain
        mock_filter.first.return_value = mock_organization
        mock_query.filter.return_value = mock_filter
        mock_db.query.return_value = mock_query
        
        # Test
        result = OrganizationService.get_organization_by_name(mock_db, "Test Corp")
        
        assert result == mock_organization
        mock_db.query.assert_called_once_with(Organization)
    
    def test_get_admin_by_email(self):
        """Test getting admin by email"""
        # Mock database session
        mock_db = Mock(spec=Session)
        mock_query = Mock()
        mock_filter = Mock()
        mock_admin = Admin(email="admin@test.com", password_hash="hashed", organization_id=1)
        
        # Set up mock chain
        mock_filter.first.return_value = mock_admin
        mock_query.filter.return_value = mock_filter
        mock_db.query.return_value = mock_query
        
        # Test
        result = OrganizationService.get_admin_by_email(mock_db, "admin@test.com")
        
        assert result == mock_admin
        mock_db.query.assert_called_once_with(Admin) 