#!/usr/bin/env python3
"""
Database base configuration and session management.
"""
from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import StaticPool
import logging
from typing import Optional

logger = logging.getLogger(__name__)

Base = declarative_base()

_engine = None
_SessionLocal = None

def get_database_url(
    database_type: str = "sqlite",
    host: Optional[str] = None,
    port: Optional[int] = None,
    database: str = "zenith_sentry",
    username: Optional[str] = None,
    password: Optional[str] = None
) -> str:
    """
    Get database connection URL based on database type.
    
    Args:
        database_type: Type of database (sqlite, postgresql)
        host: Database host
        port: Database port
        database: Database name
        username: Database username
        password: Database password
        
    Returns:
        Database connection URL
    """
    if database_type == "sqlite":
        return "sqlite:///zenith_sentry.db"
    elif database_type == "postgresql":
        if not all([host, username, password]):
            raise ValueError("PostgreSQL requires host, username, and password")
        port = port or 5432
        return f"postgresql://{username}:{password}@{host}:{port}/{database}"
    else:
        raise ValueError(f"Unsupported database type: {database_type}")

def init_database(
    database_url: Optional[str] = None,
    echo: bool = False,
    pool_size: int = 10,
    max_overflow: int = 20
) -> None:
    """
    Initialize the database engine and session factory.
    
    Args:
        database_url: Database connection URL
        echo: Whether to echo SQL statements
        pool_size: Connection pool size
        max_overflow: Maximum overflow for connection pool
    """
    global _engine, _SessionLocal
    
    if database_url is None:
        database_url = get_database_url()
    
    engine_kwargs = {"echo": echo}
    
    if database_url.startswith("sqlite"):
                                  
        engine_kwargs.update({
            "connect_args": {"check_same_thread": False},
            "poolclass": StaticPool
        })
    else:
                                      
        engine_kwargs.update({
            "pool_size": pool_size,
            "max_overflow": max_overflow,
            "pool_pre_ping": True
        })
    
    _engine = create_engine(database_url, **engine_kwargs)
    
    _SessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=_engine
    )
    
    logger.info(f"Database initialized: {database_url}")

def get_engine():
    """Get the database engine."""
    global _engine
    if _engine is None:
        init_database()
    return _engine

def get_session():
    """
    Get a database session.
    
    Returns:
        SQLAlchemy session
    """
    global _SessionLocal
    if _SessionLocal is None:
        init_database()
    return _SessionLocal()

def create_tables():
    """Create all tables in the database."""
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created")

def drop_tables():
    """Drop all tables from the database."""
    engine = get_engine()
    Base.metadata.drop_all(bind=engine)
    logger.info("Database tables dropped")
