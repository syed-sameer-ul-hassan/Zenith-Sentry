#!/usr/bin/env python3
"""
Database restore script.
Provides database restoration functionality for Zenith-Sentry database.
"""
import os
import sys
import shutil
import sqlite3
import logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zenith.db.base import get_database_url

logger = logging.getLogger(__name__)

def restore_sqlite_database(backup_path: str, db_path: str = "zenith_sentry.db") -> bool:
    """
    Restore SQLite database from backup.
    
    Args:
        backup_path: Path to backup file
        db_path: Target database path
        
    Returns:
        True if restore succeeded, False otherwise
    """
    if not os.path.exists(backup_path):
        logger.error(f"Backup file not found: {backup_path}")
        return False
    
    if os.path.exists(db_path):
                                                            
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        pre_restore_backup = f"{db_path}.pre_restore_{timestamp}"
        shutil.copy2(db_path, pre_restore_backup)
        logger.info(f"Created pre-restore backup: {pre_restore_backup}")
    
    try:
        shutil.copy2(backup_path, db_path)
        logger.info(f"SQLite database restored from: {backup_path}")
        return True
    except Exception as e:
        logger.error(f"Restore failed: {e}")
        return False

def restore_postgresql_database(
    backup_path: str,
    host: str,
    database: str,
    username: str,
    password: str,
    port: int = 5432,
    drop_existing: bool = False
) -> bool:
    """
    Restore PostgreSQL database from backup.
    
    Args:
        backup_path: Path to SQL backup file
        host: Database host
        database: Database name
        username: Database username
        password: Database password
        port: Database port
        drop_existing: Whether to drop existing database before restore
        
    Returns:
        True if restore succeeded, False otherwise
    """
    import subprocess
    
    if not os.path.exists(backup_path):
        logger.error(f"Backup file not found: {backup_path}")
        return False
    
    env = os.environ.copy()
    env["PGPASSWORD"] = password
    
    if drop_existing:
                                
        drop_cmd = [
            "dropdb",
            f"--host={host}",
            f"--port={port}",
            f"--username={username}",
            database
        ]
        try:
            subprocess.run(drop_cmd, env=env, check=True, capture_output=True)
            logger.info(f"Dropped existing database: {database}")
        except subprocess.CalledProcessError:
            logger.warning(f"Database {database} does not exist, continuing with restore")
    
    create_cmd = [
        "createdb",
        f"--host={host}",
        f"--port={port}",
        f"--username={username}",
        database
    ]
    
    try:
        subprocess.run(create_cmd, env=env, check=True, capture_output=True)
        logger.info(f"Created database: {database}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to create database: {e}")
        return False
    
    restore_cmd = [
        "psql",
        f"--host={host}",
        f"--port={port}",
        f"--username={username}",
        f"--dbname={database}",
        f"--file={backup_path}"
    ]
    
    try:
        subprocess.run(restore_cmd, env=env, check=True, capture_output=True)
        logger.info(f"PostgreSQL database restored from: {backup_path}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Restore failed: {e}")
        return False

def restore_database(backup_path: str, database_url: str = None, drop_existing: bool = False) -> bool:
    """
    Restore database based on database type.
    
    Args:
        backup_path: Path to backup file
        database_url: Database connection URL
        drop_existing: Whether to drop existing database before restore
        
    Returns:
        True if restore succeeded, False otherwise
    """
    if database_url is None:
        database_url = get_database_url()
    
    if backup_path.endswith(".db"):
                        
        db_path = database_url.replace("sqlite:///", "")
        return restore_sqlite_database(backup_path, db_path)
    elif backup_path.endswith(".sql"):
                            
        return restore_postgresql_database(
            backup_path=backup_path,
            host="localhost",
            database="zenith_sentry",
            username="zenith",
            password="password",
            drop_existing=drop_existing
        )
    else:
        logger.error(f"Unknown backup file type: {backup_path}")
        return False

def verify_restore(database_url: str = None) -> bool:
    """
    Verify database integrity after restore.
    
    Args:
        database_url: Database connection URL
        
    Returns:
        True if database is valid, False otherwise
    """
    try:
        from zenith.db.base import get_engine
        engine = get_engine()
        
        with engine.connect() as conn:
            conn.execute("SELECT 1")
        
        logger.info("Database verification successful")
        return True
    except Exception as e:
        logger.error(f"Database verification failed: {e}")
        return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Restore Zenith-Sentry database")
    parser.add_argument("backup_path", help="Path to backup file")
    parser.add_argument("--drop", action="store_true", help="Drop existing database before restore")
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO)
    
    try:
        if restore_database(args.backup_path, drop_existing=args.drop):
            verify_restore()
            print("Restore completed successfully")
        else:
            print("Restore failed")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Restore failed: {e}")
        sys.exit(1)
