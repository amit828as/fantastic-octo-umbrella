import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.connection import Base
from app.models import Organization, Admin
from passlib.context import CryptContext

# Create test database engine
TEST_DATABASE_URL = "sqlite:///./test_fastapi_org.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@pytest.fixture
def db():
    """Create test database and session"""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


def test_create_organization(db):
    """Test creating an organization"""
    organization = Organization(
        name="Test Corp",
        admin_email="admin@testcorp.com",
        admin_password_hash=pwd_context.hash("securepassword"),
        dynamic_db_connection_string="postgresql://user:pass@localhost:5432/testcorp_db"
    )
    
    db.add(organization)
    db.commit()
    db.refresh(organization)
    
    assert organization.id is not None
    assert organization.name == "Test Corp"
    assert organization.admin_email == "admin@testcorp.com"
    assert organization.created_at is not None


def test_create_admin(db):
    """Test creating an admin user"""
    # First create an organization
    organization = Organization(
        name="Test Corp",
        admin_email="admin@testcorp.com", 
        admin_password_hash=pwd_context.hash("securepassword"),
        dynamic_db_connection_string="postgresql://user:pass@localhost:5432/testcorp_db"
    )
    db.add(organization)
    db.commit()
    db.refresh(organization)
    
    # Create admin
    admin = Admin(
        email="user@testcorp.com",
        password_hash=pwd_context.hash("userpassword"),
        organization_id=organization.id
    )
    
    db.add(admin)
    db.commit()
    db.refresh(admin)
    
    assert admin.id is not None
    assert admin.email == "user@testcorp.com"
    assert admin.organization_id == organization.id
    assert admin.created_at is not None


def test_organization_admin_relationship(db):
    """Test the relationship between Organization and Admin"""
    # Create organization
    organization = Organization(
        name="Test Corp",
        admin_email="admin@testcorp.com",
        admin_password_hash=pwd_context.hash("securepassword"),
        dynamic_db_connection_string="postgresql://user:pass@localhost:5432/testcorp_db"
    )
    db.add(organization)
    db.commit()
    db.refresh(organization)
    
    # Create multiple admins
    admin1 = Admin(
        email="admin1@testcorp.com",
        password_hash=pwd_context.hash("password1"),
        organization_id=organization.id
    )
    admin2 = Admin(
        email="admin2@testcorp.com", 
        password_hash=pwd_context.hash("password2"),
        organization_id=organization.id
    )
    
    db.add(admin1)
    db.add(admin2)
    db.commit()
    
    # Test relationship
    assert len(organization.admins) == 2
    assert admin1.organization.name == "Test Corp"
    assert admin2.organization.name == "Test Corp"


def test_query_organizations(db):
    """Test querying organizations"""
    # Create test organizations
    org1 = Organization(
        name="Corp One",
        admin_email="admin1@corp1.com",
        admin_password_hash=pwd_context.hash("password1"),
        dynamic_db_connection_string="postgresql://user:pass@localhost:5432/corp1_db"
    )
    org2 = Organization(
        name="Corp Two", 
        admin_email="admin2@corp2.com",
        admin_password_hash=pwd_context.hash("password2"),
        dynamic_db_connection_string="postgresql://user:pass@localhost:5432/corp2_db"
    )
    
    db.add(org1)
    db.add(org2)
    db.commit()
    
    # Test queries
    all_orgs = db.query(Organization).all()
    assert len(all_orgs) == 2
    
    found_org = db.query(Organization).filter(Organization.name == "Corp One").first()
    assert found_org is not None
    assert found_org.admin_email == "admin1@corp1.com"


def test_unique_constraints(db):
    """Test unique constraints on organization name and admin email"""
    # Create first organization
    org1 = Organization(
        name="Unique Corp",
        admin_email="unique@corp.com",
        admin_password_hash=pwd_context.hash("password"),
        dynamic_db_connection_string="postgresql://user:pass@localhost:5432/unique_db"
    )
    db.add(org1)
    db.commit()
    
    # Try to create organization with same name - should fail
    org2 = Organization(
        name="Unique Corp",  # Same name
        admin_email="different@corp.com",
        admin_password_hash=pwd_context.hash("password"),
        dynamic_db_connection_string="postgresql://user:pass@localhost:5432/unique2_db"
    )
    db.add(org2)
    
    with pytest.raises(Exception):  # Should raise integrity error
        db.commit() 