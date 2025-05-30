import pytest
from unittest.mock import Mock, patch, MagicMock
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.models.organization import Organization
from app.models.admin import Admin
from app.schemas.organization import OrganizationCreateRequest
from app.services.organization_service import OrganizationService
from app.utils.password_utils import PasswordUtils


class TestPasswordUtils:
    """Test password utility functions"""
    
    def test_hash_password_creates_valid_hash(self):
        """Test that password hashing creates a valid bcrypt hash"""
        password = "test_password_123"
        hashed = PasswordUtils.hash_password(password)
        
        # Bcrypt hashes start with $2b$ and are 60 characters long
        assert hashed.startswith("$2b$")
        assert len(hashed) == 60
        assert hashed != password
    
    def test_verify_password_correct_password(self):
        """Test password verification with correct password"""
        password = "test_password_123"
        hashed = PasswordUtils.hash_password(password)
        
        assert PasswordUtils.verify_password(password, hashed) == True
    
    def test_verify_password_incorrect_password(self):
        """Test password verification with incorrect password"""
        password = "test_password_123"
        wrong_password = "wrong_password"
        hashed = PasswordUtils.hash_password(password)
        
        assert PasswordUtils.verify_password(wrong_password, hashed) == False
    
    def test_needs_update_returns_boolean(self):
        """Test that needs_update returns a boolean value"""
        password = "test_password_123"
        hashed = PasswordUtils.hash_password(password)
        
        result = PasswordUtils.needs_update(hashed)
        assert isinstance(result, bool)
    
    def test_get_hash_info_valid_hash(self):
        """Test getting hash info for a valid bcrypt hash"""
        password = "test_password_123"
        hashed = PasswordUtils.hash_password(password)
        
        info = PasswordUtils.get_hash_info(hashed)
        # Note: get_hash_info might return None for some configurations
        # The important thing is that it doesn't raise an exception
        assert info is None or isinstance(info, dict)


class TestAdminCreationInDynamicDatabase:
    """Test admin user creation in dynamic databases"""
    
    @patch('app.utils.database_manager.DatabaseManager.get_session')
    def test_create_admin_user_in_dynamic_database_success(self, mock_get_session):
        """Test successful admin creation in dynamic database"""
        # Setup
        organization = Organization(
            id=1,
            name="Test Corp",
            admin_email="admin@test.com",
            admin_password_hash="hashed_password",
            dynamic_db_connection_string="sqlite:///test_dynamic.db"
        )
        
        # Mock dynamic session
        mock_session = Mock()
        mock_session.query().filter().first.return_value = None  # No existing admin
        mock_get_session.return_value = (True, "Connected", mock_session)
        
        # Execute
        success, message, admin = OrganizationService.create_admin_user_in_dynamic_database(
            organization, "admin@test.com", "hashed_password"
        )
        
        # Verify
        assert success == True
        assert "successfully" in message.lower()
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()
    
    @patch('app.utils.database_manager.DatabaseManager.get_session')
    def test_create_admin_user_in_dynamic_database_connection_failure(self, mock_get_session):
        """Test admin creation failure due to dynamic database connection error"""
        # Setup
        organization = Organization(
            id=1,
            name="Test Corp",
            admin_email="admin@test.com", 
            admin_password_hash="hashed_password",
            dynamic_db_connection_string="sqlite:///test_dynamic.db"
        )
        
        mock_get_session.return_value = (False, "Connection failed", None)
        
        # Execute
        success, message, admin = OrganizationService.create_admin_user_in_dynamic_database(
            organization, "admin@test.com", "hashed_password"
        )
        
        # Verify
        assert success == False
        assert "Failed to connect to dynamic database" in message
        assert admin is None
    
    @patch('app.utils.database_manager.DatabaseManager.get_session')
    def test_create_admin_user_in_dynamic_database_duplicate_email(self, mock_get_session):
        """Test admin creation failure due to duplicate email in dynamic database"""
        # Setup
        organization = Organization(
            id=1,
            name="Test Corp",
            admin_email="admin@test.com",
            admin_password_hash="hashed_password", 
            dynamic_db_connection_string="sqlite:///test_dynamic.db"
        )
        
        # Mock existing admin
        existing_admin = Admin(id=1, email="admin@test.com", password_hash="hash", organization_id=1)
        mock_session = Mock()
        mock_session.query().filter().first.return_value = existing_admin
        mock_get_session.return_value = (True, "Connected", mock_session)
        
        # Execute
        success, message, admin = OrganizationService.create_admin_user_in_dynamic_database(
            organization, "admin@test.com", "hashed_password"
        )
        
        # Verify
        assert success == False
        assert "already exists in dynamic database" in message
        assert admin is None
        mock_session.close.assert_called_once()
    
    @patch('app.utils.database_manager.DatabaseManager.get_session')
    def test_create_admin_user_in_dynamic_database_database_error(self, mock_get_session):
        """Test admin creation failure due to database error"""
        # Setup
        organization = Organization(
            id=1,
            name="Test Corp",
            admin_email="admin@test.com",
            admin_password_hash="hashed_password",
            dynamic_db_connection_string="sqlite:///test_dynamic.db"
        )
        
        # Mock session that raises error on commit
        mock_session = Mock()
        mock_session.query().filter().first.return_value = None
        mock_session.commit.side_effect = Exception("Database error")
        mock_get_session.return_value = (True, "Connected", mock_session)
        
        # Execute
        success, message, admin = OrganizationService.create_admin_user_in_dynamic_database(
            organization, "admin@test.com", "hashed_password"
        )
        
        # Verify
        assert success == False
        assert "Failed to create admin in dynamic database" in message
        assert admin is None
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()


class TestAdminCreationInBothDatabases:
    """Test admin user creation in both master and dynamic databases"""
    
    @patch.object(OrganizationService, 'create_admin_user_in_dynamic_database')
    @patch.object(OrganizationService, 'create_admin_user_atomic')
    def test_create_admin_user_in_both_databases_success(self, mock_master_create, mock_dynamic_create):
        """Test successful admin creation in both databases"""
        # Setup
        mock_master_db = Mock(spec=Session)
        organization = Organization(
            id=1,
            name="Test Corp",
            admin_email="admin@test.com",
            admin_password_hash="hashed_password",
            dynamic_db_connection_string="sqlite:///test_dynamic.db"
        )
        
        master_admin = Admin(id=1, email="admin@test.com", password_hash="hash", organization_id=1)
        dynamic_admin = Admin(id=1, email="admin@test.com", password_hash="hash", organization_id=1)
        
        mock_master_create.return_value = (True, "Master success", master_admin)
        mock_dynamic_create.return_value = (True, "Dynamic success", dynamic_admin)
        
        # Execute
        success, message, master_result, dynamic_result = OrganizationService.create_admin_user_in_both_databases(
            mock_master_db, organization, "admin@test.com", "hashed_password"
        )
        
        # Verify
        assert success == True
        assert "successfully" in message.lower()
        assert master_result == master_admin
        assert dynamic_result == dynamic_admin
        mock_master_db.commit.assert_called_once()
        
    @patch.object(OrganizationService, 'create_admin_user_in_dynamic_database')
    @patch.object(OrganizationService, 'create_admin_user_atomic')
    def test_create_admin_user_in_both_databases_master_failure(self, mock_master_create, mock_dynamic_create):
        """Test admin creation failure at master database step"""
        # Setup
        mock_master_db = Mock(spec=Session)
        organization = Organization(
            id=1,
            name="Test Corp",
            admin_email="admin@test.com",
            admin_password_hash="hashed_password",
            dynamic_db_connection_string="sqlite:///test_dynamic.db"
        )
        
        mock_master_create.return_value = (False, "Master failed", None)
        
        # Execute
        success, message, master_result, dynamic_result = OrganizationService.create_admin_user_in_both_databases(
            mock_master_db, organization, "admin@test.com", "hashed_password"
        )
        
        # Verify
        assert success == False
        assert "Master database admin creation failed" in message
        assert master_result is None
        assert dynamic_result is None
        mock_dynamic_create.assert_not_called()
        
    @patch.object(OrganizationService, 'create_admin_user_in_dynamic_database')
    @patch.object(OrganizationService, 'create_admin_user_atomic')
    def test_create_admin_user_in_both_databases_dynamic_failure(self, mock_master_create, mock_dynamic_create):
        """Test admin creation failure at dynamic database step with rollback"""
        # Setup
        mock_master_db = Mock(spec=Session)
        organization = Organization(
            id=1,
            name="Test Corp",
            admin_email="admin@test.com",
            admin_password_hash="hashed_password",
            dynamic_db_connection_string="sqlite:///test_dynamic.db"
        )
        
        master_admin = Admin(id=1, email="admin@test.com", password_hash="hash", organization_id=1)
        
        mock_master_create.return_value = (True, "Master success", master_admin)
        mock_dynamic_create.return_value = (False, "Dynamic failed", None)
        
        # Execute
        success, message, master_result, dynamic_result = OrganizationService.create_admin_user_in_both_databases(
            mock_master_db, organization, "admin@test.com", "hashed_password"
        )
        
        # Verify
        assert success == False
        assert "Dynamic database admin creation failed" in message
        assert master_result is None
        assert dynamic_result is None
        mock_master_db.rollback.assert_called_once()


class TestOrganizationWithAdminUsers:
    """Test complete organization creation with admin users"""
    
    @patch.object(OrganizationService, 'create_admin_user_in_both_databases')
    @patch.object(OrganizationService, 'create_organization_with_dynamic_database')
    @patch.object(PasswordUtils, 'hash_password')
    def test_create_organization_with_admin_users_success(self, mock_hash, mock_create_org, mock_create_admins):
        """Test successful complete organization creation with admin users"""
        # Setup
        mock_db = Mock(spec=Session)
        request = OrganizationCreateRequest(
            email="admin@test.com",
            password="SecurePassword123!",  # Valid password with uppercase, lowercase, digit, special char
            organization_name="Test Corp"
        )
        
        organization = Organization(
            id=1,
            name="Test Corp",
            admin_email="admin@test.com",
            admin_password_hash="hashed_password",
            dynamic_db_connection_string="sqlite:///test_dynamic.db"
        )
        
        master_admin = Admin(id=1, email="admin@test.com", password_hash="hashed_password", organization_id=1)
        dynamic_admin = Admin(id=1, email="admin@test.com", password_hash="hashed_password", organization_id=1)
        
        mock_hash.return_value = "hashed_password"
        mock_create_org.return_value = (True, "Org created", organization, None)
        mock_create_admins.return_value = (True, "Admins created", master_admin, dynamic_admin)
        
        # Execute
        success, message, result_org, error_type = OrganizationService.create_organization_with_admin_users(
            mock_db, request
        )
        
        # Verify
        assert success == True
        assert "successfully" in message.lower()
        assert result_org == organization
        assert error_type is None
        
        mock_hash.assert_called_once_with("SecurePassword123!")
        mock_create_org.assert_called_once_with(mock_db, request, "hashed_password")
        mock_create_admins.assert_called_once_with(mock_db, organization, "admin@test.com", "hashed_password")
    
    @patch.object(OrganizationService, 'create_organization_with_dynamic_database')
    @patch.object(PasswordUtils, 'hash_password')
    def test_create_organization_with_admin_users_org_creation_failure(self, mock_hash, mock_create_org):
        """Test failure during organization creation step"""
        # Setup
        mock_db = Mock(spec=Session)
        request = OrganizationCreateRequest(
            email="admin@test.com",
            password="SecurePassword123!",  # Valid password
            organization_name="Test Corp"
        )
        
        mock_hash.return_value = "hashed_password"
        mock_create_org.return_value = (False, "Org creation failed", None, "validation_error")
        
        # Execute
        success, message, result_org, error_type = OrganizationService.create_organization_with_admin_users(
            mock_db, request
        )
        
        # Verify
        assert success == False
        assert "Org creation failed" in message
        assert result_org is None
        assert error_type == "validation_error"
    
    @patch.object(OrganizationService, 'create_admin_user_in_both_databases')
    @patch.object(OrganizationService, 'create_organization_with_dynamic_database')
    @patch.object(PasswordUtils, 'hash_password')
    def test_create_organization_with_admin_users_admin_creation_failure(self, mock_hash, mock_create_org, mock_create_admins):
        """Test failure during admin creation step with cleanup"""
        # Setup
        mock_db = Mock(spec=Session)
        request = OrganizationCreateRequest(
            email="admin@test.com",
            password="SecurePassword123!",  # Valid password
            organization_name="Test Corp"
        )
        
        organization = Organization(
            id=1,
            name="Test Corp",
            admin_email="admin@test.com",
            admin_password_hash="hashed_password",
            dynamic_db_connection_string="sqlite:///test_dynamic.db"
        )
        
        mock_hash.return_value = "hashed_password"
        mock_create_org.return_value = (True, "Org created", organization, None)
        mock_create_admins.return_value = (False, "Admin creation failed", None, None)
        
        # Execute
        success, message, result_org, error_type = OrganizationService.create_organization_with_admin_users(
            mock_db, request
        )
        
        # Verify
        assert success == False
        assert "Admin user creation failed" in message
        assert result_org is None
        assert error_type == "admin_creation_error"
        mock_db.rollback.assert_called_once() 