import uuid
import re
import os
import sqlite3
import subprocess
from datetime import datetime, UTC
from typing import Optional, Tuple, Dict
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool, QueuePool
from sqlalchemy.engine import Engine

try:
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
    POSTGRESQL_AVAILABLE = True
except ImportError:
    POSTGRESQL_AVAILABLE = False

try:
    from alembic.config import Config
    from alembic import command
    ALEMBIC_AVAILABLE = True
except ImportError:
    ALEMBIC_AVAILABLE = False

try:
    from sqlalchemy import create_engine, Engine
    from sqlalchemy.orm import sessionmaker, Session
    from sqlalchemy.pool import QueuePool, StaticPool
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False


class DatabaseManager:
    """Service for managing dynamic database creation and connections"""
    
    # Class-level connection pool storage
    _connection_pools: Dict[str, Engine] = {}
    _session_makers: Dict[str, sessionmaker] = {}
    
    @staticmethod
    def generate_database_name(organization_id: int, organization_name: str) -> str:
        """
        Generate a unique database name for an organization.
        
        Args:
            organization_id: The ID of the organization
            organization_name: The name of the organization for readability
            
        Returns:
            A unique database name string compatible with SQLite and PostgreSQL
        """
        # Clean organization name for database naming (remove special chars, spaces)
        clean_name = re.sub(r'[^a-zA-Z0-9]', '_', organization_name.lower())
        clean_name = re.sub(r'_+', '_', clean_name)  # Replace multiple underscores with single
        clean_name = clean_name.strip('_')  # Remove leading/trailing underscores
        
        # Ensure name starts with letter (database naming requirement)
        if not clean_name or not clean_name[0].isalpha():
            clean_name = f"org_{clean_name}"
        
        # Generate timestamp-based suffix for uniqueness
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        
        # Add short UUID for extra uniqueness
        short_uuid = str(uuid.uuid4())[:8]
        
        # Combine all parts: org_id + clean_name + timestamp + uuid
        db_name = f"org_{organization_id}_{clean_name}_{timestamp}_{short_uuid}"
        
        # Ensure total length doesn't exceed database limits (PostgreSQL: 63 chars)
        if len(db_name) > 60:
            # Truncate the clean_name part if needed
            max_name_length = 60 - len(f"org_{organization_id}_{timestamp}_{short_uuid}")
            if max_name_length > 0:
                clean_name = clean_name[:max_name_length]
            else:
                clean_name = ""
            db_name = f"org_{organization_id}_{clean_name}_{timestamp}_{short_uuid}"
            if len(db_name) > 60:
                # Final fallback - just use org_id, timestamp, and uuid
                db_name = f"org_{organization_id}_{timestamp}_{short_uuid}"
        
        return db_name
    
    @staticmethod
    def is_valid_database_name(db_name: str) -> bool:
        """
        Validate if a database name conforms to SQLite and PostgreSQL conventions.
        
        Args:
            db_name: Database name to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not db_name:
            return False
        
        # Check length (PostgreSQL limit is 63 characters)
        if len(db_name) > 63:
            return False
        
        # Must start with letter or underscore
        if not (db_name[0].isalpha() or db_name[0] == '_'):
            return False
        
        # Can only contain letters, numbers, underscores
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', db_name):
            return False
        
        # Cannot be a reserved keyword (common ones)
        reserved_keywords = {
            'user', 'table', 'index', 'database', 'schema', 'column', 
            'select', 'insert', 'update', 'delete', 'create', 'drop'
        }
        if db_name.lower() in reserved_keywords:
            return False
        
        return True
    
    @staticmethod
    def create_database(database_name: str, db_type: str = "sqlite", 
                       postgresql_config: Optional[dict] = None) -> Tuple[bool, str, Optional[str]]:
        """
        Create a new database instance.
        
        Args:
            database_name: Name of the database to create
            db_type: Type of database ("sqlite" or "postgresql")
            postgresql_config: Configuration for PostgreSQL connection
                              (host, port, user, password, admin_db)
            
        Returns:
            Tuple of (success: bool, message: str, connection_string: Optional[str])
        """
        # Validate database name
        if not DatabaseManager.is_valid_database_name(database_name):
            return False, f"Invalid database name: {database_name}", None
        
        try:
            if db_type.lower() == "sqlite":
                return DatabaseManager._create_sqlite_database(database_name)
            elif db_type.lower() == "postgresql":
                if not POSTGRESQL_AVAILABLE:
                    return False, "PostgreSQL support not available (psycopg2 not installed)", None
                if not postgresql_config:
                    return False, "PostgreSQL configuration required", None
                return DatabaseManager._create_postgresql_database(database_name, postgresql_config)
            else:
                return False, f"Unsupported database type: {db_type}", None
                
        except Exception as e:
            return False, f"Database creation failed: {str(e)}", None
    
    @staticmethod
    def _create_sqlite_database(database_name: str) -> Tuple[bool, str, str]:
        """
        Create SQLite database file.
        
        Args:
            database_name: Name of the database
            
        Returns:
            Tuple of (success, message, connection_string)
        """
        try:
            # Create databases directory if it doesn't exist
            db_dir = Path("databases")
            db_dir.mkdir(exist_ok=True)
            
            # Create database file path
            db_path = db_dir / f"{database_name}.db"
            
            # Check if database already exists
            if db_path.exists():
                return False, f"Database file already exists: {db_path}", None
            
            # Create SQLite database by connecting to it
            conn = sqlite3.connect(str(db_path))
            
            # Create a simple table to initialize the database
            conn.execute("""
                CREATE TABLE _db_info (
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    database_name TEXT NOT NULL,
                    version TEXT DEFAULT '1.0'
                )
            """)
            
            # Insert initialization record
            conn.execute(
                "INSERT INTO _db_info (database_name) VALUES (?)", 
                (database_name,)
            )
            
            conn.commit()
            conn.close()
            
            connection_string = f"sqlite:///{db_path.absolute()}"
            return True, f"SQLite database created successfully: {db_path}", connection_string
            
        except Exception as e:
            # Clean up partial file if it exists
            if 'db_path' in locals() and db_path.exists():
                try:
                    db_path.unlink()
                except:
                    pass
            raise e
    
    @staticmethod 
    def _create_postgresql_database(database_name: str, config: dict) -> Tuple[bool, str, str]:
        """
        Create PostgreSQL database.
        
        Args:
            database_name: Name of the database to create
            config: PostgreSQL configuration dict with keys:
                   host, port, user, password, admin_db
                   
        Returns:
            Tuple of (success, message, connection_string)
        """
        try:
            # Connect to admin database (usually 'postgres')
            admin_conn = psycopg2.connect(
                host=config.get('host', 'localhost'),
                port=config.get('port', 5432),
                database=config.get('admin_db', 'postgres'),
                user=config['user'],
                password=config['password']
            )
            
            # Set autocommit mode for database creation
            admin_conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            
            cursor = admin_conn.cursor()
            
            # Check if database already exists
            cursor.execute(
                "SELECT 1 FROM pg_database WHERE datname = %s", 
                (database_name,)
            )
            
            if cursor.fetchone():
                cursor.close()
                admin_conn.close()
                return False, f"Database already exists: {database_name}", None
            
            # Create the database
            cursor.execute(f'CREATE DATABASE "{database_name}"')
            
            cursor.close()
            admin_conn.close()
            
            # Build connection string
            connection_string = (
                f"postgresql://{config['user']}:{config['password']}"
                f"@{config.get('host', 'localhost')}:{config.get('port', 5432)}"
                f"/{database_name}"
            )
            
            return True, f"PostgreSQL database created successfully: {database_name}", connection_string
            
        except psycopg2.Error as e:
            return False, f"PostgreSQL error: {str(e)}", None
        except Exception as e:
            return False, f"Unexpected error: {str(e)}", None
    
    @staticmethod
    def migrate_database(connection_string: str, db_type: str = "sqlite") -> Tuple[bool, str]:
        """
        Run schema migrations on a database.
        For dynamic databases, we'll directly create the tables using SQLAlchemy models.
        
        Args:
            connection_string: Database connection string
            db_type: Type of database ("sqlite" or "postgresql")
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not SQLALCHEMY_AVAILABLE:
            return False, "SQLAlchemy not available for migrations"
        
        try:
            # Create engine for the dynamic database
            engine = create_engine(connection_string)
            
            # Import the models to get the table definitions
            from app.models.organization import Organization
            from app.models.admin import Admin
            
            # Create all tables defined in the models
            from sqlalchemy.orm import declarative_base
            
            # Get the base class that both models inherit from
            Base = Organization.metadata.bind = engine
            
            # Create all tables
            Organization.metadata.create_all(engine)
            
            # Verify tables were created
            with engine.connect() as conn:
                if db_type == "sqlite":
                    result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('organizations', 'admins')"))
                    tables = [row[0] for row in result.fetchall()]
                else:
                    result = conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_name IN ('organizations', 'admins')"))
                    tables = [row[0] for row in result.fetchall()]
                
                if 'organizations' in tables and 'admins' in tables:
                    return True, "Database schema created successfully"
                else:
                    return False, f"Tables not created properly. Found: {tables}"
            
        except Exception as e:
            return False, f"Migration failed: {str(e)}"
    
    @staticmethod
    def store_connection_info(db_session, organization_id: int, connection_string: str) -> Tuple[bool, str]:
        """
        Store connection information for a dynamic database in the master database.
        
        Args:
            db_session: SQLAlchemy database session for the master database
            organization_id: ID of the organization
            connection_string: Connection string for the dynamic database
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            from app.models.organization import Organization
            
            # Find the organization
            organization = db_session.query(Organization).filter(
                Organization.id == organization_id
            ).first()
            
            if not organization:
                return False, f"Organization with ID {organization_id} not found"
            
            # Update the connection string
            organization.dynamic_db_connection_string = connection_string
            db_session.commit()
            
            return True, f"Connection information stored for organization {organization_id}"
            
        except Exception as e:
            db_session.rollback()
            return False, f"Failed to store connection information: {str(e)}"
    
    @staticmethod
    def get_connection_info(db_session, organization_id: int) -> Tuple[bool, str, Optional[str]]:
        """
        Retrieve connection information for an organization's dynamic database.
        
        Args:
            db_session: SQLAlchemy database session for the master database
            organization_id: ID of the organization
            
        Returns:
            Tuple of (success: bool, message: str, connection_string: Optional[str])
        """
        try:
            from app.models.organization import Organization
            
            # Find the organization
            organization = db_session.query(Organization).filter(
                Organization.id == organization_id
            ).first()
            
            if not organization:
                return False, f"Organization with ID {organization_id} not found", None
            
            if not organization.dynamic_db_connection_string:
                return False, f"No dynamic database configured for organization {organization_id}", None
            
            return True, "Connection information retrieved", organization.dynamic_db_connection_string
            
        except Exception as e:
            return False, f"Failed to retrieve connection information: {str(e)}", None
    
    @staticmethod
    def create_connection_pool(connection_string: str, pool_size: int = 5, max_overflow: int = 10) -> Tuple[bool, str, Optional[Engine]]:
        """
        Create a connection pool for a database.
        
        Args:
            connection_string: Database connection string
            pool_size: Number of connections to maintain in the pool
            max_overflow: Maximum number of connections that can overflow the pool
            
        Returns:
            Tuple of (success: bool, message: str, engine: Optional[Engine])
        """
        if not SQLALCHEMY_AVAILABLE:
            return False, "SQLAlchemy not available for connection pooling", None
        
        try:
            # Determine pool class based on database type
            if connection_string.startswith("sqlite"):
                # SQLite uses StaticPool for thread safety
                engine = create_engine(
                    connection_string,
                    poolclass=StaticPool,
                    pool_pre_ping=True,
                    echo=False
                )
            else:
                # PostgreSQL and other databases use QueuePool
                engine = create_engine(
                    connection_string,
                    poolclass=QueuePool,
                    pool_size=pool_size,
                    max_overflow=max_overflow,
                    pool_pre_ping=True,
                    echo=False
                )
            
            # Test the connection
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            return True, "Connection pool created successfully", engine
            
        except Exception as e:
            return False, f"Failed to create connection pool: {str(e)}", None
    
    @staticmethod
    def get_connection_pool(connection_string: str) -> Tuple[bool, str, Optional[Engine]]:
        """
        Get or create a connection pool for a database.
        
        Args:
            connection_string: Database connection string
            
        Returns:
            Tuple of (success: bool, message: str, engine: Optional[Engine])
        """
        # Check if pool already exists
        if connection_string in DatabaseManager._connection_pools:
            engine = DatabaseManager._connection_pools[connection_string]
            return True, "Retrieved existing connection pool", engine
        
        # Create new pool
        success, message, engine = DatabaseManager.create_connection_pool(connection_string)
        
        if success and engine:
            # Store the pool for reuse
            DatabaseManager._connection_pools[connection_string] = engine
            # Create session maker
            DatabaseManager._session_makers[connection_string] = sessionmaker(bind=engine)
        
        return success, message, engine
    
    @staticmethod
    def get_session(connection_string: str) -> Tuple[bool, str, Optional[Session]]:
        """
        Get a database session from the connection pool.
        
        Args:
            connection_string: Database connection string
            
        Returns:
            Tuple of (success: bool, message: str, session: Optional[Session])
        """
        try:
            # Get or create connection pool
            success, message, engine = DatabaseManager.get_connection_pool(connection_string)
            
            if not success:
                return False, f"Failed to get connection pool: {message}", None
            
            # Get session maker
            if connection_string not in DatabaseManager._session_makers:
                return False, "Session maker not found", None
            
            session_maker = DatabaseManager._session_makers[connection_string]
            session = session_maker()
            
            return True, "Database session created", session
            
        except Exception as e:
            return False, f"Failed to create session: {str(e)}", None
    
    @staticmethod
    def close_connection_pool(connection_string: str) -> Tuple[bool, str]:
        """
        Close and remove a connection pool.
        
        Args:
            connection_string: Database connection string
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            if connection_string in DatabaseManager._connection_pools:
                engine = DatabaseManager._connection_pools[connection_string]
                engine.dispose()
                del DatabaseManager._connection_pools[connection_string]
                
                if connection_string in DatabaseManager._session_makers:
                    del DatabaseManager._session_makers[connection_string]
                
                return True, "Connection pool closed successfully"
            else:
                return True, "Connection pool not found (already closed)"
                
        except Exception as e:
            return False, f"Failed to close connection pool: {str(e)}"
    
    @staticmethod
    def close_all_connection_pools() -> Tuple[bool, str]:
        """
        Close all connection pools.
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            closed_count = 0
            for connection_string in list(DatabaseManager._connection_pools.keys()):
                success, _ = DatabaseManager.close_connection_pool(connection_string)
                if success:
                    closed_count += 1
            
            return True, f"Closed {closed_count} connection pools"
            
        except Exception as e:
            return False, f"Failed to close connection pools: {str(e)}"
    
    @staticmethod
    def create_and_migrate_database(
        organization_id: int,
        organization_name: str,
        db_type: str = "sqlite",
        postgresql_config: Optional[dict] = None
    ) -> Tuple[bool, str, Optional[str], Optional[str]]:
        """
        Create a database and run migrations on it.
        
        Args:
            organization_id: ID of the organization
            organization_name: Name of the organization
            db_type: Type of database ("sqlite" or "postgresql")
            postgresql_config: PostgreSQL configuration if needed
            
        Returns:
            Tuple of (success: bool, message: str, database_name: str, connection_string: str)
        """
        # Generate database name
        db_name = DatabaseManager.generate_database_name(organization_id, organization_name)
        
        # Create the database
        success, create_message, conn_str = DatabaseManager.create_database(
            db_name, db_type, postgresql_config
        )
        
        if not success:
            return False, f"Database creation failed: {create_message}", None, None
        
        # Run migrations on the new database
        migrate_success, migrate_message = DatabaseManager.migrate_database(conn_str, db_type)
        
        if not migrate_success:
            # Clean up created database on migration failure
            DatabaseManager._cleanup_database(db_name, db_type, postgresql_config)
            return False, f"Database created but migration failed: {migrate_message}", db_name, None
        
        return True, f"Database created and migrated successfully", db_name, conn_str
    
    @staticmethod
    def _cleanup_database(database_name: str, db_type: str, postgresql_config: Optional[dict] = None):
        """
        Clean up a database in case of failures.
        
        Args:
            database_name: Name of the database to clean up
            db_type: Type of database
            postgresql_config: PostgreSQL configuration if needed
        """
        try:
            if db_type.lower() == "sqlite":
                db_path = Path("databases") / f"{database_name}.db"
                if db_path.exists():
                    db_path.unlink()
            elif db_type.lower() == "postgresql" and postgresql_config:
                # Connect and drop database
                admin_conn = psycopg2.connect(
                    host=postgresql_config.get('host', 'localhost'),
                    port=postgresql_config.get('port', 5432),
                    database=postgresql_config.get('admin_db', 'postgres'),
                    user=postgresql_config['user'],
                    password=postgresql_config['password']
                )
                admin_conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
                cursor = admin_conn.cursor()
                cursor.execute(f'DROP DATABASE IF EXISTS "{database_name}"')
                cursor.close()
                admin_conn.close()
        except Exception:
            # Ignore cleanup errors
            pass 