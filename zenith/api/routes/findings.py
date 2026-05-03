#!/usr/bin/env python3
"""
Findings-related API routes.
"""
from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from datetime import datetime
from zenith.api.models import FindingResponse, RiskLevel, Severity
from zenith.api.routes import _shared

router = APIRouter()

_findings: List[FindingResponse] = _shared.findings

@router.get("/", response_model=List[FindingResponse], summary="List all findings")
async def list_findings(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    risk_level: Optional[RiskLevel] = Query(None),
    severity: Optional[Severity] = Query(None),
    since: Optional[datetime] = Query(None)
) -> List[FindingResponse]:
    """
    List all security findings with optional filtering.
    
    Args:
        limit: Maximum number of findings to return
        offset: Number of findings to skip
        risk_level: Filter by risk level
        severity: Filter by severity
        since: Filter findings since this timestamp
        
    Returns:
        List of findings
    """
    filtered = _findings
    
    if risk_level:
        filtered = [f for f in filtered if f.risk == risk_level]
    
    if severity:
        filtered = [f for f in filtered if f.severity == severity]
    
    if since:
        filtered = [f for f in filtered if f.timestamp >= since]
    
    filtered.sort(key=lambda x: x.timestamp, reverse=True)
    
    return filtered[offset:offset+limit]

@router.get("/{finding_id}", response_model=FindingResponse, summary="Get a specific finding")
async def get_finding(finding_id: str) -> FindingResponse:
    """
    Get a specific finding by ID.
    
    Args:
        finding_id: Finding identifier
        
    Returns:
        Finding details
    """
    for finding in _findings:
        if finding.id == finding_id:
            return finding
    
    raise HTTPException(status_code=404, detail="Finding not found")

@router.get("/stats/summary", summary="Get findings summary statistics")
async def get_findings_summary() -> dict:
    """
    Get summary statistics for all findings.
    
    Returns:
        Dictionary with statistics
    """
    total = len(_findings)
    
    risk_counts = {}
    for risk in RiskLevel:
        risk_counts[risk.value] = len([f for f in _findings if f.risk == risk])
    
    severity_counts = {}
    for severity in Severity:
        severity_counts[severity.value] = len([f for f in _findings if f.severity == severity])
    
    return {
        "total": total,
        "by_risk": risk_counts,
        "by_severity": severity_counts,
        "last_updated": datetime.utcnow().isoformat() if _findings else None
    }
