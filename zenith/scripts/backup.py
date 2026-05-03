#!/usr/bin/env python3
"""
Database backup script.
Provides automated backup functionality for Zenith-Sentry database.
"""
import os
import sys
import shutil
import sqlite3
import logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zenith.db.base import get_database_url, get_engine

logger = logging.getLogger(__name__)

def backup_sqlite_database(db_path: str, backup_dir: str = "./backups") -> str:
    """
    Backup SQLite database.
    
    Args:
        db_path: Path to SQLite database file
        backup_dir: Directory to store backups
        
    Returns:
        Path to backup file
    """
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database file not found: {db_path}")
    
    os.makedirs(backup_dir, exist_ok=True)
    
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"zenith_sentry_backup_{timestamp}.db"
    backup_path = os.path.join(backup_dir, backup_filename)
    
    shutil.copy2(db_path, backup_path)
    
    logger.info(f"SQLite database backed up to: {backup_path}")
    
    return backup_path

def backup_postgresql_database(
    host: str,
    database: str,
    username: str,
    password: str,
    port: int = 5432,
    backup_dir: str = "./backups"
) -> str:
    """
    Backup PostgreSQL database using pg_dump.
    
    Args:
        host: Database host
        database: Database name
        username: Database username
        password: Database password
        port: Database port
        backup_dir: Directory to store backups
        
    Returns:
        Path to backup file
    """
    import subprocess
    
    os.makedirs(backup_dir, exist_ok=True)
    
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"zenith_sentry_backup_{timestamp}.sql"
    backup_path = os.path.join(backup_dir, backup_filename)
    
    env = os.environ.copy()
    env["PGPASSWORD"] = password
    
    cmd = [
        "pg_dump",
        f"--host={host}",
        f"--port={port}",
        f"--username={username}",
        f"--dbname={database}",
        "--verbose",
        "--format=plain",
        f"--file={backup_path}"
    ]
    
    try:
        subprocess.run(cmd, env=env, check=True, capture_output=True, text=True)
        logger.info(f"PostgreSQL database backed up to: {backup_path}")
    except subprocess.CalledProcessError as e:
        logger.error(f"pg_dump failed: {e}")
        raise
    
    return backup_path

def backup_database(database_url: str = None, backup_dir: str = "./backups") -> str:
    """
    Backup database based on database type.
    
    Args:
        database_url: Database connection URL
        backup_dir: Directory to store backups
        
    Returns:
        Path to backup file
    """
    if database_url is None:
        database_url = get_database_url()
    
    if database_url.startswith("sqlite"):
                                      
        db_path = database_url.replace("sqlite:///", "")
        return backup_sqlite_database(db_path, backup_dir)
    elif database_url.startswith("postgresql"):
                              
        return backup_postgresql_database(
            host="localhost",                             
            database="zenith_sentry",
            username="zenith",
            password="password",
            backup_dir=backup_dir
        )
    else:
        raise ValueError(f"Unsupported database type in URL: {database_url}")

def verify_backup(backup_path: str) -> bool:
    """
    Verify backup file integrity.
    
    Args:
        backup_path: Path to backup file
        
    Returns:
        True if backup is valid, False otherwise
    """
    if not os.path.exists(backup_path):
        logger.error(f"Backup file not found: {backup_path}")
        return False
    
    file_size = os.path.getsize(backup_path)
    if file_size == 0:
        logger.error(f"Backup file is empty: {backup_path}")
        return False
    
    if backup_path.endswith(".db"):
        try:
            conn = sqlite3.connect(backup_path)
            conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            conn.close()
            logger.info(f"SQLite backup verified: {backup_path}")
            return True
        except sqlite3.Error as e:
            logger.error(f"SQLite backup verification failed: {e}")
            return False
    
    if backup_path.endswith(".sql"):
        with open(backup_path, 'r') as f:
            content = f.read()
        if "CREATE TABLE" in content or "INSERT INTO" in content:
            logger.info(f"SQL backup appears valid: {backup_path}")
            return True
        else:
            logger.error(f"SQL backup appears invalid: {backup_path}")
            return False
    
    logger.warning(f"Could not verify backup: {backup_path}")
    return True

def cleanup_old_backups(backup_dir: str = "./backups", keep_count: int = 7) -> int:
    """
    Clean up old backups, keeping only the most recent ones.
    
    Args:
        backup_dir: Directory containing backups
        keep_count: Number of backups to keep
        
    Returns:
        Number of backups deleted
    """
    if not os.path.exists(backup_dir):
        logger.warning(f"Backup directory not found: {backup_dir}")
        return 0
    
    backup_files = []
    for filename in os.listdir(backup_dir):
        if filename.startswith("zenith_sentry_backup_"):
            filepath = os.path.join(backup_dir, filename)
            backup_files.append((filepath, os.path.getmtime(filepath)))
    
    backup_files.sort(key=lambda x: x[1])
    
    deleted_count = 0
    while len(backup_files) > keep_count:
        filepath, _ = backup_files.pop(0)
        os.remove(filepath)
        deleted_count += 1
        logger.info(f"Deleted old backup: {filepath}")
    
    return deleted_count

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    try:
        backup_path = backup_database()
        verify_backup(backup_path)
        cleanup_old_backups()
        print(f"Backup completed successfully: {backup_path}")
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        sys.exit(1)
