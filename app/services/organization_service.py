from typing import Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func

from app.models.organization import Organization
from app.models.admin import Admin
from app.schemas.organization import OrganizationCreateRequest
from app.utils.database_manager import DatabaseManager
from app.utils.password_utils import PasswordUtils


class OrganizationService:
    """Service for organization-related operations"""
    
    @staticmethod
    def check_organization_name_exists(db: Session, organization_name: str) -> bool:
        """
        Check if an organization name already exists in the database.
        
        Args:
            db: Database session
            organization_name: Name to check for uniqueness
            
        Returns:
            True if organization name exists, False otherwise
        """
        # Case-insensitive check for organization name
        existing_org = db.query(Organization).filter(
            func.lower(Organization.name) == func.lower(organization_name.strip())
        ).first()
        
        return existing_org is not None
    
    @staticmethod
    def check_admin_email_exists(db: Session, email: str) -> bool:
        """
        Check if an admin email already exists in the database.
        
        Args:
            db: Database session
            email: Email to check for uniqueness
            
        Returns:
            True if email exists, False otherwise
        """
        # Case-insensitive check for admin email
        existing_admin = db.query(Admin).filter(
            func.lower(Admin.email) == func.lower(email.strip())
        ).first()
        
        return existing_admin is not None
    
    @staticmethod
    def validate_organization_creation_request(
        db: Session, 
        request: OrganizationCreateRequest
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Validate organization creation request for uniqueness constraints.
        
        Args:
            db: Database session
            request: Organization creation request data
            
        Returns:
            Tuple of (is_valid: bool, error_message: str, error_type: Optional[str])
        """
        # Check organization name uniqueness
        if OrganizationService.check_organization_name_exists(db, request.organization_name):
            return False, f"Organization name '{request.organization_name}' already exists", "duplicate_organization"
        
        # Check admin email uniqueness
        if OrganizationService.check_admin_email_exists(db, request.email):
            return False, f"Admin email '{request.email}' already exists", "duplicate_email"
        
        return True, "Validation passed", None
    
    @staticmethod
    def create_organization_atomic(
        db: Session,
        organization_name: str,
        admin_email: str,
        admin_password_hash: str,
        dynamic_db_connection_string: str
    ) -> Tuple[bool, str, Optional[Organization]]:
        """
        Create organization with atomic transaction to prevent race conditions.
        
        Args:
            db: Database session
            organization_name: Name of the organization
            admin_email: Admin email address
            admin_password_hash: Hashed admin password
            dynamic_db_connection_string: Connection string for dynamic database
            
        Returns:
            Tuple of (success: bool, message: str, organization: Optional[Organization])
        """
        try:
            # Begin transaction (implicit with session)
            
            # Double-check uniqueness within transaction to handle race conditions
            if OrganizationService.check_organization_name_exists(db, organization_name):
                return False, f"Organization name '{organization_name}' already exists", None
            
            if OrganizationService.check_admin_email_exists(db, admin_email):
                return False, f"Admin email '{admin_email}' already exists", None
            
            # Create organization
            organization = Organization(
                name=organization_name.strip(),
                admin_email=admin_email.strip().lower(),
                admin_password_hash=admin_password_hash,
                dynamic_db_connection_string=dynamic_db_connection_string
            )
            
            db.add(organization)
            db.flush()  # Flush to get the ID without committing
            
            return True, "Organization created successfully", organization
            
        except IntegrityError as e:
            db.rollback()
            # Check if it's a duplicate key error
            if "unique constraint" in str(e).lower() or "duplicate" in str(e).lower():
                if "name" in str(e).lower():
                    return False, f"Organization name '{organization_name}' already exists", None
                elif "email" in str(e).lower():
                    return False, f"Admin email '{admin_email}' already exists", None
                else:
                    return False, f"Duplicate constraint violation", None
            else:
                return False, f"Database integrity error: {str(e)}", None
        except Exception as e:
            db.rollback()
            return False, f"Failed to create organization: {str(e)}", None
    
    @staticmethod
    def create_organization_with_dynamic_database(
        db: Session,
        request: OrganizationCreateRequest,
        admin_password_hash: str
    ) -> Tuple[bool, str, Optional[Organization], Optional[str]]:
        """
        Complete organization creation workflow including dynamic database creation.
        
        Args:
            db: Database session
            request: Organization creation request
            admin_password_hash: Hashed admin password
            
        Returns:
            Tuple of (success: bool, message: str, organization: Optional[Organization], error_type: Optional[str])
        """
        try:
            # Step 1: Validate request
            is_valid, validation_message, error_type = OrganizationService.validate_organization_creation_request(
                db, request
            )
            if not is_valid:
                return False, validation_message, None, error_type
            
            # Step 2: Generate dynamic database name
            db_manager = DatabaseManager()
            # Generate a temporary organization ID for database naming (will use actual ID after creation)
            temp_org_id = 0  # Will be updated after organization creation
            db_name = db_manager.generate_database_name(temp_org_id, request.organization_name)
            
            # Step 3: Create and migrate dynamic database
            db_success, db_message, _, connection_string = db_manager.create_and_migrate_database(
                temp_org_id, request.organization_name
            )
            if not db_success:
                return False, f"Failed to create dynamic database: {db_message}", None, "database_creation_error"
            
            # Step 4: Get connection string for the new database
            if not connection_string:
                # Cleanup: Remove the created database if connection string generation fails
                try:
                    db_manager._cleanup_database(db_name, "sqlite")
                except Exception:
                    pass  # Log this in production
                return False, "Failed to generate connection string for dynamic database", None, "connection_error"
            
            # Step 5: Create organization record with dynamic database connection
            org_success, org_message, organization = OrganizationService.create_organization_atomic(
                db, 
                request.organization_name,
                request.email,
                admin_password_hash,
                connection_string
            )
            
            if not org_success:
                # Cleanup: Remove the created database if organization creation fails
                try:
                    db_manager._cleanup_database(db_name, "sqlite")
                except Exception:
                    pass  # Log this in production
                return False, org_message, None, "organization_creation_error"
            
            # Step 6: Store connection information in organization record
            store_success, store_message = db_manager.store_connection_info(
                db, organization.id, connection_string
            )
            
            if not store_success:
                # Rollback organization creation and cleanup database
                db.rollback()
                try:
                    db_manager._cleanup_database(db_name, "sqlite")
                except Exception:
                    pass  # Log this in production
                return False, f"Failed to store connection info: {store_message}", None, "storage_error"
            
            # Step 7: Commit the transaction
            db.commit()
            
            return True, "Organization and dynamic database created successfully", organization, None
            
        except Exception as e:
            db.rollback()
            return False, f"Unexpected error during organization creation: {str(e)}", None, "unexpected_error"
    
    @staticmethod
    def create_admin_user_atomic(
        db: Session,
        email: str,
        password_hash: str,
        organization_id: int
    ) -> Tuple[bool, str, Optional[Admin]]:
        """
        Create admin user with atomic transaction.
        
        Args:
            db: Database session
            email: Admin email address
            password_hash: Hashed password
            organization_id: ID of the organization
            
        Returns:
            Tuple of (success: bool, message: str, admin: Optional[Admin])
        """
        try:
            # Double-check email uniqueness within transaction
            if OrganizationService.check_admin_email_exists(db, email):
                return False, f"Admin email '{email}' already exists", None
            
            # Create admin user
            admin = Admin(
                email=email.strip().lower(),
                password_hash=password_hash,
                organization_id=organization_id
            )
            
            db.add(admin)
            db.flush()  # Flush to get the ID without committing
            
            return True, "Admin user created successfully", admin
            
        except IntegrityError as e:
            db.rollback()
            # Check if it's a duplicate key error
            if "unique constraint" in str(e).lower() or "duplicate" in str(e).lower():
                return False, f"Admin email '{email}' already exists", None
            else:
                return False, f"Database integrity error: {str(e)}", None
        except Exception as e:
            db.rollback()
            return False, f"Failed to create admin user: {str(e)}", None
    
    @staticmethod
    def get_organization_by_id(db: Session, organization_id: int) -> Optional[Organization]:
        """
        Get organization by ID.
        
        Args:
            db: Database session
            organization_id: ID of the organization
            
        Returns:
            Organization instance or None if not found
        """
        return db.query(Organization).filter(Organization.id == organization_id).first()
    
    @staticmethod
    def get_organization_by_name(db: Session, organization_name: str) -> Optional[Organization]:
        """
        Get organization by name (case-insensitive).
        
        Args:
            db: Database session
            organization_name: Name of the organization
            
        Returns:
            Organization instance or None if not found
        """
        return db.query(Organization).filter(
            func.lower(Organization.name) == func.lower(organization_name.strip())
        ).first()
    
    @staticmethod
    def get_admin_by_email(db: Session, email: str) -> Optional[Admin]:
        """
        Get admin by email (case-insensitive).
        
        Args:
            db: Database session
            email: Email address
            
        Returns:
            Admin instance or None if not found
        """
        return db.query(Admin).filter(
            func.lower(Admin.email) == func.lower(email.strip())
        ).first()
    
    @staticmethod
    def create_admin_user_in_dynamic_database(
        organization: Organization,
        email: str,
        password_hash: str
    ) -> Tuple[bool, str, Optional[Admin]]:
        """
        Create admin user in the organization's dynamic database.
        
        Args:
            organization: Organization instance with dynamic_db_connection_string
            email: Admin email address
            password_hash: Hashed password
            
        Returns:
            Tuple of (success: bool, message: str, admin: Optional[Admin])
        """
        try:
            # Get connection to dynamic database
            db_manager = DatabaseManager()
            success, message, dynamic_session = db_manager.get_session(
                organization.dynamic_db_connection_string
            )
            
            if not success:
                return False, f"Failed to connect to dynamic database: {message}", None
            
            try:
                # Check if admin already exists in dynamic database
                existing_admin = dynamic_session.query(Admin).filter(
                    func.lower(Admin.email) == func.lower(email.strip())
                ).first()
                
                if existing_admin:
                    return False, f"Admin email '{email}' already exists in dynamic database", None
                
                # Create admin user in dynamic database
                admin = Admin(
                    email=email.strip().lower(),
                    password_hash=password_hash,
                    organization_id=organization.id
                )
                
                dynamic_session.add(admin)
                dynamic_session.commit()
                
                return True, "Admin user created successfully in dynamic database", admin
                
            except Exception as e:
                dynamic_session.rollback()
                return False, f"Failed to create admin in dynamic database: {str(e)}", None
            finally:
                dynamic_session.close()
                
        except Exception as e:
            return False, f"Dynamic database connection error: {str(e)}", None
    
    @staticmethod
    def create_admin_user_in_both_databases(
        master_db: Session,
        organization: Organization,
        email: str,
        password_hash: str
    ) -> Tuple[bool, str, Optional[Admin], Optional[Admin]]:
        """
        Create admin user in both master and dynamic databases atomically.
        
        Args:
            master_db: Master database session
            organization: Organization instance
            email: Admin email address
            password_hash: Hashed password
            
        Returns:
            Tuple of (success: bool, message: str, master_admin: Optional[Admin], dynamic_admin: Optional[Admin])
        """
        master_admin = None
        dynamic_admin = None
        
        try:
            # Step 1: Create admin in master database
            master_success, master_message, master_admin = OrganizationService.create_admin_user_atomic(
                master_db, email, password_hash, organization.id
            )
            
            if not master_success:
                return False, f"Master database admin creation failed: {master_message}", None, None
            
            # Step 2: Create admin in dynamic database
            dynamic_success, dynamic_message, dynamic_admin = OrganizationService.create_admin_user_in_dynamic_database(
                organization, email, password_hash
            )
            
            if not dynamic_success:
                # Rollback master database admin creation
                try:
                    master_db.rollback()
                    return False, f"Dynamic database admin creation failed: {dynamic_message}", None, None
                except Exception as rollback_error:
                    return False, f"Dynamic admin creation failed and master rollback failed: {dynamic_message}, {str(rollback_error)}", None, None
            
            # Step 3: Commit master database transaction
            master_db.commit()
            
            return True, "Admin user created successfully in both databases", master_admin, dynamic_admin
            
        except Exception as e:
            # Ensure master database is rolled back on any error
            try:
                master_db.rollback()
            except Exception:
                pass
            return False, f"Unexpected error creating admin users: {str(e)}", None, None
    
    @staticmethod
    def create_organization_with_admin_users(
        db: Session,
        request: OrganizationCreateRequest
    ) -> Tuple[bool, str, Optional[Organization], Optional[str]]:
        """
        Complete organization creation workflow including dynamic database and admin users in both databases.
        
        Args:
            db: Master database session
            request: Organization creation request
            
        Returns:
            Tuple of (success: bool, message: str, organization: Optional[Organization], error_type: Optional[str])
        """
        try:
            # Step 1: Hash the admin password
            admin_password_hash = PasswordUtils.hash_password(request.password)
            
            # Step 2: Create organization with dynamic database
            org_success, org_message, organization, error_type = OrganizationService.create_organization_with_dynamic_database(
                db, request, admin_password_hash
            )
            
            if not org_success:
                return False, org_message, None, error_type
            
            # Step 3: Create admin users in both databases
            admin_success, admin_message, master_admin, dynamic_admin = OrganizationService.create_admin_user_in_both_databases(
                db, organization, request.email, admin_password_hash
            )
            
            if not admin_success:
                # Cleanup: Remove the created organization and dynamic database
                try:
                    db.rollback()
                    db_manager = DatabaseManager()
                    # Extract database name from connection string for cleanup
                    if organization and organization.dynamic_db_connection_string:
                        # This is a simplified cleanup - in production you'd need more robust db name extraction
                        pass  # TODO: Add proper cleanup logic
                except Exception:
                    pass  # Log this in production
                return False, f"Admin user creation failed: {admin_message}", None, "admin_creation_error"
            
            return True, "Organization and admin users created successfully in both databases", organization, None
            
        except Exception as e:
            db.rollback()
            return False, f"Unexpected error during organization creation: {str(e)}", None, "unexpected_error" 