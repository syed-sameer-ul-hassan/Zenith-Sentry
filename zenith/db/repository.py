#!/usr/bin/env python3
"""
Database repository for query operations.
Provides search, filter, and aggregation capabilities.
"""
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging

from zenith.db.models import Scan, Finding, SystemEvent, User, APIKey

logger = logging.getLogger(__name__)

class ScanRepository:
    """Repository for Scan queries."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_by_id(self, scan_id: str) -> Optional[Scan]:
        """Get a scan by ID."""
        return self.db.query(Scan).filter(Scan.id == scan_id).first()
    
    def get_all(
        self,
        limit: int = 50,
        offset: int = 0,
        status: Optional[str] = None
    ) -> List[Scan]:
        """Get all scans with optional filtering."""
        query = self.db.query(Scan)
        
        if status:
            query = query.filter(Scan.status == status)
        
        return query.order_by(Scan.start_time.desc()).offset(offset).limit(limit).all()
    
    def get_active_scans(self) -> List[Scan]:
        """Get all currently active scans."""
        return self.db.query(Scan).filter(Scan.status == "in_progress").all()
    
    def create(self, scan: Scan) -> Scan:
        """Create a new scan."""
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan
    
    def update_status(self, scan_id: str, status: str) -> Optional[Scan]:
        """Update scan status."""
        scan = self.get_by_id(scan_id)
        if scan:
            scan.status = status
            if status == "completed":
                scan.end_time = datetime.utcnow()
            self.db.commit()
            self.db.refresh(scan)
        return scan

class FindingRepository:
    """Repository for Finding queries."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_by_id(self, finding_id: str) -> Optional[Finding]:
        """Get a finding by ID."""
        return self.db.query(Finding).filter(Finding.id == finding_id).first()
    
    def get_all(
        self,
        limit: int = 50,
        offset: int = 0,
        risk_level: Optional[str] = None,
        severity: Optional[str] = None,
        scan_id: Optional[str] = None,
        resolved: Optional[bool] = None,
        since: Optional[datetime] = None
    ) -> List[Finding]:
        """Get all findings with optional filtering."""
        query = self.db.query(Finding)
        
        if risk_level:
            query = query.filter(Finding.risk == risk_level)
        
        if severity:
            query = query.filter(Finding.severity == severity)
        
        if scan_id:
            query = query.filter(Finding.scan_id == scan_id)
        
        if resolved is not None:
            query = query.filter(Finding.resolved == resolved)
        
        if since:
            query = query.filter(Finding.timestamp >= since)
        
        return query.order_by(Finding.timestamp.desc()).offset(offset).limit(limit).all()
    
    def search(self, search_term: str, limit: int = 50) -> List[Finding]:
        """Search findings by description or evidence."""
        search_pattern = f"%{search_term}%"
        return self.db.query(Finding).filter(
            or_(
                Finding.description.ilike(search_pattern),
                Finding.tactic.ilike(search_pattern)
            )
        ).limit(limit).all()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get finding statistics."""
        total = self.db.query(func.count(Finding.id)).scalar()
        
        risk_counts = {}
        for risk in ["low", "medium", "high", "critical"]:
            count = self.db.query(func.count(Finding.id)).filter(Finding.risk == risk).scalar()
            risk_counts[risk] = count
        
        severity_counts = {}
        for severity in ["low", "medium", "high", "critical"]:
            count = self.db.query(func.count(Finding.id)).filter(Finding.severity == severity).scalar()
            severity_counts[severity] = count
        
        return {
            "total": total,
            "by_risk": risk_counts,
            "by_severity": severity_counts
        }
    
    def create(self, finding: Finding) -> Finding:
        """Create a new finding."""
        self.db.add(finding)
        self.db.commit()
        self.db.refresh(finding)
        return finding
    
    def mark_resolved(self, finding_id: str) -> Optional[Finding]:
        """Mark a finding as resolved."""
        finding = self.get_by_id(finding_id)
        if finding:
            finding.resolved = True
            finding.resolved_at = datetime.utcnow()
            self.db.commit()
            self.db.refresh(finding)
        return finding

class SystemEventRepository:
    """Repository for SystemEvent queries."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create(self, event: SystemEvent) -> SystemEvent:
        """Create a new system event."""
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event
    
    def get_recent(self, limit: int = 100) -> List[SystemEvent]:
        """Get recent system events."""
        return self.db.query(SystemEvent).order_by(
            SystemEvent.timestamp.desc()
        ).limit(limit).all()
    
    def get_by_type(self, event_type: str, limit: int = 50) -> List[SystemEvent]:
        """Get events by type."""
        return self.db.query(SystemEvent).filter(
            SystemEvent.event_type == event_type
        ).order_by(SystemEvent.timestamp.desc()).limit(limit).all()
