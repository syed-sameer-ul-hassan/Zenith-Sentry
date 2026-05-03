#!/usr/bin/env python3
"""
Data retention policies for database cleanup.
Provides automatic cleanup of old data with configurable retention periods.
"""
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_
import logging

from zenith.db.models import Finding, SystemEvent, Scan

logger = logging.getLogger(__name__)

class RetentionPolicy:
    """Data retention policy configuration."""
    
    FINDINGS_RETENTION_DAYS = 90
    EVENTS_RETENTION_DAYS = 30
    SCANS_RETENTION_DAYS = 180
    
    MAX_FINDINGS = 10000
    MAX_EVENTS = 5000
    MAX_SCANS = 1000

def cleanup_old_findings(db: Session, retention_days: int = None) -> int:
    """
    Clean up old findings based on retention policy.
    
    Args:
        db: Database session
        retention_days: Retention period in days (default: from policy)
        
    Returns:
        Number of findings deleted
    """
    if retention_days is None:
        retention_days = RetentionPolicy.FINDINGS_RETENTION_DAYS
    
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
    
    deleted = db.query(Finding).filter(
        and_(
            Finding.timestamp < cutoff_date,
            Finding.resolved == True                                 
        )
    ).delete()
    
    db.commit()
    logger.info(f"Deleted {deleted} old findings (older than {retention_days} days)")
    
    return deleted

def cleanup_old_events(db: Session, retention_days: int = None) -> int:
    """
    Clean up old system events based on retention policy.
    
    Args:
        db: Database session
        retention_days: Retention period in days (default: from policy)
        
    Returns:
        Number of events deleted
    """
    if retention_days is None:
        retention_days = RetentionPolicy.EVENTS_RETENTION_DAYS
    
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
    
    deleted = db.query(SystemEvent).filter(
        SystemEvent.timestamp < cutoff_date
    ).delete()
    
    db.commit()
    logger.info(f"Deleted {deleted} old events (older than {retention_days} days)")
    
    return deleted

def cleanup_old_scans(db: Session, retention_days: int = None) -> int:
    """
    Clean up old scans based on retention policy.
    
    Args:
        db: Database session
        retention_days: Retention period in days (default: from policy)
        
    Returns:
        Number of scans deleted
    """
    if retention_days is None:
        retention_days = RetentionPolicy.SCANS_RETENTION_DAYS
    
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
    
    deleted = db.query(Scan).filter(
        and_(
            Scan.start_time < cutoff_date,
            Scan.status == "completed"
        )
    ).delete()
    
    db.commit()
    logger.info(f"Deleted {deleted} old scans (older than {retention_days} days)")
    
    return deleted

def enforce_max_records(db: Session) -> dict:
    """
    Enforce maximum record limits to prevent database bloat.
    
    Args:
        db: Database session
        
    Returns:
        Dictionary with deletion counts
    """
    stats = {}
    
    finding_count = db.query(func.count(Finding.id)).scalar()
    if finding_count > RetentionPolicy.MAX_FINDINGS:
                                             
        excess = finding_count - RetentionPolicy.MAX_FINDINGS
        oldest_findings = db.query(Finding).order_by(
            Finding.timestamp.asc()
        ).limit(excess).all()
        
        for finding in oldest_findings:
            db.delete(finding)
        
        db.commit()
        stats["findings_deleted"] = excess
        logger.info(f"Deleted {excess} findings to enforce max limit")
    
    event_count = db.query(func.count(SystemEvent.id)).scalar()
    if event_count > RetentionPolicy.MAX_EVENTS:
        excess = event_count - RetentionPolicy.MAX_EVENTS
        oldest_events = db.query(SystemEvent).order_by(
            SystemEvent.timestamp.asc()
        ).limit(excess).all()
        
        for event in oldest_events:
            db.delete(event)
        
        db.commit()
        stats["events_deleted"] = excess
        logger.info(f"Deleted {excess} events to enforce max limit")
    
    scan_count = db.query(func.count(Scan.id)).scalar()
    if scan_count > RetentionPolicy.MAX_SCANS:
        excess = scan_count - RetentionPolicy.MAX_SCANS
        oldest_scans = db.query(Scan).order_by(
            Scan.start_time.asc()
        ).limit(excess).all()
        
        for scan in oldest_scans:
            db.delete(scan)
        
        db.commit()
        stats["scans_deleted"] = excess
        logger.info(f"Deleted {excess} scans to enforce max limit")
    
    return stats

def run_retention_cleanup(db: Session, findings_days: int = None, events_days: int = None, scans_days: int = None) -> dict:
    """
    Run all retention cleanup operations.
    
    Args:
        db: Database session
        findings_days: Custom retention period for findings
        events_days: Custom retention period for events
        scans_days: Custom retention period for scans
        
    Returns:
        Dictionary with cleanup statistics
    """
    stats = {}
    
    stats["findings_deleted"] = cleanup_old_findings(db, findings_days)
    stats["events_deleted"] = cleanup_old_events(db, events_days)
    stats["scans_deleted"] = cleanup_old_scans(db, scans_days)
    
    max_records_stats = enforce_max_records(db)
    stats.update(max_records_stats)
    
    stats["total_deleted"] = sum(stats.values())
    
    return stats
