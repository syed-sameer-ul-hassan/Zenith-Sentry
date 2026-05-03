#!/usr/bin/env python3
"""
SQLAlchemy ORM models for Zenith-Sentry database.
"""
from sqlalchemy import Column, String, Integer, DateTime, Text, JSON, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from zenith.db.base import Base

class Scan(Base):
    """Scan model representing a security scan."""
    __tablename__ = "scans"
    
    id = Column(String(36), primary_key=True, index=True)
    scan_type = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False, default="in_progress")
    start_time = Column(DateTime, nullable=False, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    ebpf_enabled = Column(Boolean, default=False)
    mitigation_enabled = Column(Boolean, default=False)
    target_dirs = Column(JSON, nullable=True)
    summary = Column(JSON, nullable=True, default={})
    
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

class Finding(Base):
    """Finding model representing a security finding."""
    __tablename__ = "findings"
    
    id = Column(String(100), primary_key=True, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=True)
    module = Column(String(100), nullable=False)
    risk = Column(String(20), nullable=False)
    severity = Column(String(20), nullable=False)
    tactic = Column(String(20), nullable=True)
    description = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=True, default={})
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)
    
    scan = relationship("Scan", back_populates="findings")

class SystemEvent(Base):
    """System event model for logging system events."""
    __tablename__ = "system_events"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(50), nullable=False)
    source = Column(String(100), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    metadata = Column(JSON, nullable=True, default={})
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)

class User(Base):
    """User model for authentication and authorization."""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="viewer")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

class APIKey(Base):
    """API key model for API authentication."""
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)
