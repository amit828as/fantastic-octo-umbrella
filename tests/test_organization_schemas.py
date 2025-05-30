import pytest
from pydantic import ValidationError
from app.schemas.organization import (
    OrganizationCreateRequest, 
    OrganizationCreateResponse, 
    OrganizationCreateError
)


class TestOrganizationCreateRequest:
    """Test OrganizationCreateRequest schema and validation"""
    
    def test_valid_organization_request(self):
        """Test valid organization creation request"""
        data = {
            "email": "admin@example.com",
            "password": "SecurePassword123!",
            "organization_name": "Test Corporation"
        }
        
        request = OrganizationCreateRequest(**data)
        
        assert request.email == "admin@example.com"
        assert request.password == "SecurePassword123!"
        assert request.organization_name == "Test Corporation"
    
    def test_invalid_email_format(self):
        """Test invalid email format validation"""
        invalid_emails = [
            "invalid-email",
            "test@",
            "@example.com",
            "test.example.com",
            "",
            "test@.com",
            "test@domain.",
        ]
        
        for email in invalid_emails:
            with pytest.raises(ValidationError) as exc_info:
                OrganizationCreateRequest(
                    email=email,
                    password="SecurePassword123!",
                    organization_name="Test Corp"
                )
            assert "email" in str(exc_info.value).lower()
    
    def test_valid_email_formats(self):
        """Test valid email formats"""
        valid_emails = [
            "test@example.com",
            "admin@company.co.uk",
            "user.name@domain.org",
            "test+tag@example.com",
            "user123@test-domain.com"
        ]
        
        for email in valid_emails:
            request = OrganizationCreateRequest(
                email=email,
                password="SecurePassword123!",
                organization_name="Test Corp"
            )
            assert request.email == email
    
    def test_password_too_short(self):
        """Test password minimum length validation"""
        short_passwords = ["1234567", "Abc123!", "Short1!"]
        
        for password in short_passwords:
            with pytest.raises(ValidationError) as exc_info:
                OrganizationCreateRequest(
                    email="test@example.com",
                    password=password,
                    organization_name="Test Corp"
                )
            assert "at least 8 characters" in str(exc_info.value)
    
    def test_password_missing_uppercase(self):
        """Test password uppercase letter requirement"""
        with pytest.raises(ValidationError) as exc_info:
            OrganizationCreateRequest(
                email="test@example.com",
                password="lowercase123!",
                organization_name="Test Corp"
            )
        assert "uppercase letter" in str(exc_info.value)
    
    def test_password_missing_lowercase(self):
        """Test password lowercase letter requirement"""
        with pytest.raises(ValidationError) as exc_info:
            OrganizationCreateRequest(
                email="test@example.com",
                password="UPPERCASE123!",
                organization_name="Test Corp"
            )
        assert "lowercase letter" in str(exc_info.value)
    
    def test_password_missing_digit(self):
        """Test password digit requirement"""
        with pytest.raises(ValidationError) as exc_info:
            OrganizationCreateRequest(
                email="test@example.com",
                password="NoDigitsHere!",
                organization_name="Test Corp"
            )
        assert "digit" in str(exc_info.value)
    
    def test_password_missing_special_character(self):
        """Test password special character requirement"""
        with pytest.raises(ValidationError) as exc_info:
            OrganizationCreateRequest(
                email="test@example.com",
                password="NoSpecialChars123",
                organization_name="Test Corp"
            )
        assert "special character" in str(exc_info.value)
    
    def test_valid_passwords(self):
        """Test valid passwords that meet all requirements"""
        valid_passwords = [
            "SecurePassword123!",
            "MyP@ssw0rd",
            "Complex123#",
            "StrongPass1$",
            "ValidPassword2%"
        ]
        
        for password in valid_passwords:
            request = OrganizationCreateRequest(
                email="test@example.com",
                password=password,
                organization_name="Test Corp"
            )
            assert request.password == password
    
    def test_password_too_long(self):
        """Test password maximum length validation"""
        long_password = "Aa1!" + "A" * 124  # 128 characters with proper validation
        
        with pytest.raises(ValidationError) as exc_info:
            OrganizationCreateRequest(
                email="test@example.com",
                password=long_password + "X",  # 129 characters
                organization_name="Test Corp"
            )
        assert "String should have at most 128 characters" in str(exc_info.value)
    
    def test_organization_name_too_short(self):
        """Test organization name minimum length"""
        with pytest.raises(ValidationError) as exc_info:
            OrganizationCreateRequest(
                email="test@example.com",
                password="SecurePassword123!",
                organization_name="A"
            )
        assert "String should have at least 2 characters" in str(exc_info.value)
    
    def test_organization_name_too_long(self):
        """Test organization name maximum length"""
        long_name = "A" * 101  # 101 characters
        
        with pytest.raises(ValidationError) as exc_info:
            OrganizationCreateRequest(
                email="test@example.com",
                password="SecurePassword123!",
                organization_name=long_name
            )
        assert "String should have at most 100 characters" in str(exc_info.value)
    
    def test_organization_name_empty_or_whitespace(self):
        """Test organization name empty or whitespace validation"""
        invalid_names = ["", "   ", "\t", "\n", "  \t  "]
        
        for name in invalid_names:
            with pytest.raises(ValidationError) as exc_info:
                OrganizationCreateRequest(
                    email="test@example.com",
                    password="SecurePassword123!",
                    organization_name=name
                )
            error_str = str(exc_info.value)
            # Can be caught by either min length or custom validation
            assert ("String should have at least 2 characters" in error_str or 
                   "cannot be empty or only whitespace" in error_str)
    
    def test_organization_name_invalid_characters(self):
        """Test organization name invalid character validation"""
        invalid_names = [
            "Corp@123",
            "Test#Company",
            "Name&Co",
            "Corp*Inc",
            "Test/Company",
            "Name\\Co"
        ]
        
        for name in invalid_names:
            with pytest.raises(ValidationError) as exc_info:
                OrganizationCreateRequest(
                    email="test@example.com",
                    password="SecurePassword123!",
                    organization_name=name
                )
            assert "can only contain letters, numbers, spaces, hyphens, and periods" in str(exc_info.value)
    
    def test_organization_name_only_special_characters(self):
        """Test organization name with only special characters"""
        invalid_names = ["---", "...", "   ", "- . -"]
        
        for name in invalid_names:
            with pytest.raises(ValidationError) as exc_info:
                OrganizationCreateRequest(
                    email="test@example.com",
                    password="SecurePassword123!",
                    organization_name=name
                )
            # This should trigger either the whitespace or special-only validation
            error_str = str(exc_info.value)
            assert ("cannot be empty or only whitespace" in error_str or 
                   "must contain at least one letter or number" in error_str)
    
    def test_valid_organization_names(self):
        """Test valid organization names"""
        valid_names = [
            "Test Corporation",
            "ABC Company Inc.",
            "Tech-Solutions",
            "Company123",
            "My Corp.",
            "Start-Up Co",
            "Enterprise Solutions Ltd."
        ]
        
        for name in valid_names:
            request = OrganizationCreateRequest(
                email="test@example.com",
                password="SecurePassword123!",
                organization_name=name
            )
            assert request.organization_name == name.strip()
    
    def test_organization_name_whitespace_trimming(self):
        """Test organization name whitespace trimming"""
        name_with_whitespace = "  Test Corporation  "
        
        request = OrganizationCreateRequest(
            email="test@example.com",
            password="SecurePassword123!",
            organization_name=name_with_whitespace
        )
        
        assert request.organization_name == "Test Corporation"


class TestOrganizationCreateResponse:
    """Test OrganizationCreateResponse schema"""
    
    def test_successful_response(self):
        """Test successful organization creation response"""
        data = {
            "success": True,
            "message": "Organization created successfully",
            "organization_id": 1,
            "admin_id": 1
        }
        
        response = OrganizationCreateResponse(**data)
        
        assert response.success is True
        assert response.message == "Organization created successfully"
        assert response.organization_id == 1
        assert response.admin_id == 1
    
    def test_response_without_optional_fields(self):
        """Test response without optional fields"""
        data = {
            "success": False,
            "message": "Creation failed"
        }
        
        response = OrganizationCreateResponse(**data)
        
        assert response.success is False
        assert response.message == "Creation failed"
        assert response.organization_id is None
        assert response.admin_id is None


class TestOrganizationCreateError:
    """Test OrganizationCreateError schema"""
    
    def test_error_response(self):
        """Test error response schema"""
        data = {
            "success": False,
            "message": "Organization name already exists",
            "error_type": "duplicate_organization",
            "details": {"organization_name": "Test Corp"}
        }
        
        error = OrganizationCreateError(**data)
        
        assert error.success is False
        assert error.message == "Organization name already exists"
        assert error.error_type == "duplicate_organization"
        assert error.details == {"organization_name": "Test Corp"}
    
    def test_error_response_without_details(self):
        """Test error response without details"""
        data = {
            "message": "Validation error",
            "error_type": "validation_error"
        }
        
        error = OrganizationCreateError(**data)
        
        assert error.success is False  # Default value
        assert error.message == "Validation error"
        assert error.error_type == "validation_error"
        assert error.details is None 