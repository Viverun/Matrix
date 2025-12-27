"""
Database configuration and session management.

This module provides async SQLAlchemy configuration with connection pooling,
session management, and database initialization utilities for the Matrix
security scanner.
"""
from typing import AsyncGenerator, Optional, List
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    AsyncEngine,
    async_sessionmaker
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import event, text
from sqlalchemy.exc import SQLAlchemyError, OperationalError
from config import get_settings
from core.logger import get_logger

# Initialize structured logger
logger = get_logger(__name__)

# Load application settings
settings = get_settings()

# Database configuration constants
DB_POOL_SIZE = 5
DB_MAX_OVERFLOW = 10
DB_POOL_TIMEOUT = 30
DB_POOL_RECYCLE = 3600  # 1 hour
DB_ECHO_ENABLED = settings.debug


class DatabaseConfig:
    """
    Centralized database configuration and engine management.
    
    This class encapsulates all database-related configuration and provides
    utilities for engine management, connection testing, and monitoring.
    """
    
    def __init__(self) -> None:
        """Initialize database configuration and create async engine."""
        self.engine: Optional[AsyncEngine] = None
        self.session_maker: Optional[async_sessionmaker] = None
        self._initialize_engine()
    
    def _initialize_engine(self) -> None:
        """Create and configure the async database engine."""
        try:
            logger.info(f"Initializing database engine: {self._get_safe_url()}")
            
            self.engine = create_async_engine(
                settings.database_url,
                echo=DB_ECHO_ENABLED,
                future=True,
                pool_size=DB_POOL_SIZE,
                max_overflow=DB_MAX_OVERFLOW,
                pool_timeout=DB_POOL_TIMEOUT,
                pool_recycle=DB_POOL_RECYCLE,
                pool_pre_ping=True,  # Verify connections before using
            )
            
            # Configure SQLite-specific optimizations
            if "sqlite" in settings.database_url.lower():
                self._configure_sqlite_optimizations()
            
            # Create session factory
            self.session_maker = async_sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )
            
            logger.info("Database engine initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database engine: {str(e)}", exc_info=True)
            raise
    
    def _configure_sqlite_optimizations(self) -> None:
        """Configure SQLite-specific performance optimizations."""
        logger.info("Configuring SQLite optimizations (WAL mode, synchronous=NORMAL)")
        
        @event.listens_for(self.engine.sync_engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            """Set SQLite PRAGMAs for optimal performance."""
            cursor = dbapi_connection.cursor()
            try:
                # Enable WAL mode for better concurrency
                cursor.execute("PRAGMA journal_mode=WAL")
                
                # Optimize for speed while maintaining safety
                cursor.execute("PRAGMA synchronous=NORMAL")
                
                # Cache size (negative value = KB, -64000 = 64MB)
                cursor.execute("PRAGMA cache_size=-64000")
                
                # Enable foreign key constraints
                cursor.execute("PRAGMA foreign_keys=ON")
                
                logger.debug("SQLite PRAGMAs configured successfully")
            except Exception as e:
                logger.error(f"Failed to set SQLite PRAGMAs: {str(e)}")
            finally:
                cursor.close()
    
    def _get_safe_url(self) -> str:
        """
        Get database URL with credentials masked for logging.
        
        Returns:
            Database URL with password replaced by asterisks.
        """
        url = settings.database_url
        if "@" in url:
            # Mask password in URL (e.g., postgresql://user:***@host/db)
            parts = url.split("@")
            if ":" in parts[0]:
                user_part = parts[0].split(":")[0]
                return f"{user_part}:***@{parts[1]}"
        return url
    
    async def get_connection_pool_status(self) -> dict:
        """
        Get current connection pool statistics.
        
        Returns:
            Dictionary containing pool size, checked out connections, etc.
        """
        if not self.engine:
            return {"error": "Engine not initialized"}
        
        pool = self.engine.pool
        return {
            "size": pool.size(),
            "checked_out": pool.checkedout(),
            "overflow": pool.overflow(),
            "total_connections": pool.size() + pool.overflow(),
        }
    
    async def health_check(self) -> bool:
        """
        Perform a database health check.
        
        Returns:
            True if database is accessible and responding, False otherwise.
        """
        if not self.engine:
            logger.error("Health check failed: Engine not initialized")
            return False
        
        try:
            async with self.engine.begin() as conn:
                result = await conn.execute(text("SELECT 1"))
                result.fetchone()
            logger.debug("Database health check passed")
            return True
        except OperationalError as e:
            logger.error(f"Database health check failed: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during health check: {str(e)}", exc_info=True)
            return False
    
    async def dispose(self) -> None:
        """Dispose of the database engine and close all connections."""
        if self.engine:
            logger.info("Disposing database engine and closing connections")
            await self.engine.dispose()
            logger.info("Database engine disposed successfully")


# Global database configuration instance
db_config = DatabaseConfig()

# Expose engine and session maker for backward compatibility
engine = db_config.engine
async_session_maker = db_config.session_maker


class Base(DeclarativeBase):
    """
    Base class for all database models.
    
    All SQLAlchemy models should inherit from this class to ensure
    proper table creation and metadata management.
    """
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for getting database sessions with automatic transaction management.
    
    This generator provides a database session that automatically commits on success
    and rolls back on exceptions. It should be used with FastAPI's Depends() or
    similar dependency injection systems.
    
    Yields:
        AsyncSession: An async SQLAlchemy session.
        
    Raises:
        SQLAlchemyError: If there's an error during session operations.
        
    Example:
        ```python
        @app.get("/users")
        async def get_users(db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(User))
            return result.scalars().all()
        ```
    """
    if not async_session_maker:
        logger.error("Session maker not initialized")
        raise RuntimeError("Database session maker not initialized")
    
    async with async_session_maker() as session:
        try:
            logger.debug("Database session created")
            yield session
            await session.commit()
            logger.debug("Database transaction committed")
        except SQLAlchemyError as e:
            await session.rollback()
            logger.error(f"Database error, transaction rolled back: {str(e)}")
            raise
        except Exception as e:
            await session.rollback()
            logger.error(f"Unexpected error, transaction rolled back: {str(e)}", exc_info=True)
            raise
        finally:
            await session.close()
            logger.debug("Database session closed")


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """
    Context manager for getting database sessions in non-FastAPI contexts.
    
    This provides the same functionality as get_db() but as a context manager
    for use outside of FastAPI dependency injection.
    
    Yields:
        AsyncSession: An async SQLAlchemy session.
        
    Example:
        ```python
        async with get_db_context() as db:
            result = await db.execute(select(User))
            users = result.scalars().all()
        ```
    """
    async for session in get_db():
        yield session


async def init_db() -> None:
    """
    Initialize database tables based on defined models.
    
    This function creates all tables defined in SQLAlchemy models that inherit
    from Base. It should be called during application startup.
    
    Raises:
        SQLAlchemyError: If table creation fails.
    """
    if not engine:
        logger.error("Cannot initialize database: Engine not initialized")
        raise RuntimeError("Database engine not initialized")
    
    try:
        logger.info("Initializing database tables...")
        
        async with engine.begin() as conn:
            # Get list of tables to create
            table_names = list(Base.metadata.tables.keys())
            
            if not table_names:
                logger.warning("No tables defined in Base.metadata")
            else:
                logger.info(f"Creating {len(table_names)} tables: {', '.join(table_names)}")
            
            # Create all tables
            await conn.run_sync(Base.metadata.create_all)
            
        logger.info("Database tables initialized successfully")
        
        # Perform health check after initialization
        is_healthy = await db_config.health_check()
        if is_healthy:
            logger.info("Database health check passed")
        else:
            logger.warning("Database health check failed after initialization")
            
    except SQLAlchemyError as e:
        logger.error(f"Failed to initialize database tables: {str(e)}", exc_info=True)
        raise
    except Exception as e:
        logger.error(f"Unexpected error during database initialization: {str(e)}", exc_info=True)
        raise


async def close_db() -> None:
    """
    Close database connections and dispose of the engine.
    
    This function should be called during application shutdown to ensure
    all database connections are properly closed.
    """
    try:
        await db_config.dispose()
    except Exception as e:
        logger.error(f"Error closing database: {str(e)}", exc_info=True)
        raise


async def get_table_info() -> List[dict]:
    """
    Get information about all database tables.
    
    Returns:
        List of dictionaries containing table names and column information.
        
    Example:
        ```python
        tables = await get_table_info()
        for table in tables:
            print(f"Table: {table['name']}, Columns: {table['columns']}")
        ```
    """
    if not engine:
        logger.error("Cannot get table info: Engine not initialized")
        return []
    
    tables_info = []
    
    for table_name, table in Base.metadata.tables.items():
        columns = [
            {
                "name": column.name,
                "type": str(column.type),
                "nullable": column.nullable,
                "primary_key": column.primary_key,
            }
            for column in table.columns
        ]
        
        tables_info.append({
            "name": table_name,
            "columns": columns,
            "column_count": len(columns),
        })
    
    logger.debug(f"Retrieved info for {len(tables_info)} tables")
    return tables_info


async def drop_all_tables() -> None:
    """
    Drop all database tables.
    
    WARNING: This will permanently delete all data. Use only for testing
    or development environments.
    
    Raises:
        SQLAlchemyError: If table deletion fails.
    """
    if not engine:
        logger.error("Cannot drop tables: Engine not initialized")
        raise RuntimeError("Database engine not initialized")
    
    logger.warning("Dropping all database tables - THIS WILL DELETE ALL DATA")
    
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        logger.warning("All database tables dropped successfully")
    except SQLAlchemyError as e:
        logger.error(f"Failed to drop tables: {str(e)}", exc_info=True)
        raise


async def vacuum_database() -> None:
    """
    Vacuum the SQLite database to reclaim space and optimize performance.
    
    This is only applicable for SQLite databases. For other databases,
    this function will log a warning and return.
    """
    if not engine:
        logger.error("Cannot vacuum: Engine not initialized")
        return
    
    if "sqlite" not in settings.database_url.lower():
        logger.info("VACUUM command only applicable to SQLite databases")
        return
    
    try:
        logger.info("Running VACUUM on SQLite database...")
        async with engine.begin() as conn:
            await conn.execute(text("VACUUM"))
        logger.info("Database VACUUM completed successfully")
    except Exception as e:
        logger.error(f"Failed to vacuum database: {str(e)}", exc_info=True)