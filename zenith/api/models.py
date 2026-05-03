#!/usr/bin/env python3
"""
Pydantic models for FastAPI request/response validation.
"""
from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class RiskLevel(str, Enum):
    """Risk level enumeration."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Severity(str, Enum):
    """Severity level enumeration."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class FindingBase(BaseModel):
    """Base model for security findings."""
    id: str = Field(..., description="Unique finding identifier")
    module: str = Field(..., description="Detector module that generated the finding")
    risk: RiskLevel = Field(..., description="Risk level")
    severity: Severity = Field(..., description="Severity level")
    tactic: Optional[str] = Field(None, description="MITRE ATT&CK tactic ID")
    description: str = Field(..., description="Finding description")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Evidence data")

class FindingResponse(FindingBase):
    """Finding response model with timestamps."""
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Finding timestamp")
    
    class Config:
        orm_mode = True

class ScanRequest(BaseModel):
    """Scan request model."""
    scan_type: str = Field(..., description="Type of scan to run")
    ebpf_enabled: bool = Field(default=False, description="Enable eBPF monitoring")
    mitigation_enabled: bool = Field(default=False, description="Enable automatic mitigation")
    target_dirs: Optional[List[str]] = Field(None, description="Target directories to scan")
    
    json_output: bool = Field(default=False, description="Return JSON-formatted results")

    @validator('scan_type')
    def validate_scan_type(cls, v):
                                                                                           
        if not isinstance(v, str) or not v.strip():
            raise ValueError("scan_type must be a non-empty string")
        return v.strip().lower()

class ScanResponse(BaseModel):
    """Scan response model."""
    scan_id: str = Field(..., description="Unique scan identifier")
    status: str = Field(..., description="Scan status")
    start_time: datetime = Field(default_factory=datetime.utcnow, description="Scan start time")
    end_time: Optional[datetime] = Field(None, description="Scan end time")
    findings: List[FindingResponse] = Field(default_factory=list, description="List of findings")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Scan summary statistics")

class SystemStatus(BaseModel):
    """System status response model."""
    api_status: str = Field(..., description="API status")
    version: str = Field(..., description="API version")
    features: Dict[str, bool] = Field(default_factory=dict, description="Feature availability")
    system_info: Dict[str, Any] = Field(default_factory=dict, description="System information")

class ErrorResponse(BaseModel):
    """Error response model."""
    detail: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Error code")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")
