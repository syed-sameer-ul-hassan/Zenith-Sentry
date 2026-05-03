#!/usr/bin/env python3
"""
Scan-related API routes.
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List
import uuid
import logging
from datetime import datetime
from zenith.api.models import ScanRequest, ScanResponse, FindingResponse, RiskLevel, Severity
from zenith.api.routes import _shared

logger = logging.getLogger(__name__)
router = APIRouter()

_scans: dict = _shared.scans

def _run_scan_task(scan_id: str, request: ScanRequest) -> None:
    """Execute a real scan using ZenithEngine collectors + detectors."""
    import types
    try:
        from zenith.collectors import ProcessCollector, NetworkCollector, SystemCollector
        from zenith.registry import PluginRegistry
        from zenith.config import ConfigLoader

        cfg = ConfigLoader(None)
        registry = PluginRegistry()
        registry.load_plugins()

        procs = ProcessCollector().collect()
        conns = NetworkCollector().collect()
        sys_files = SystemCollector(
            cfg.get("persistence", {}).get("scan_dirs", [])
        ).collect()

        detectors = registry.instantiate(
            procs=procs, conns=conns, sys_files=sys_files,
            ebpf_events=[], config=cfg.config,
        )

        raw_findings = []
        for det in detectors:
            try:
                raw_findings.extend(det.analyze())
            except Exception as exc:
                logger.warning("Detector %s failed: %s", getattr(det, 'name', det), exc)

        out_findings: List[FindingResponse] = []
        for f in raw_findings:
            try:
                risk_name = getattr(f.risk, 'name', str(f.risk)).lower()
                sev_name = getattr(f.severity, 'name', str(f.severity)).lower()
                out_findings.append(FindingResponse(
                    id=str(getattr(f, 'id', uuid.uuid4())),
                    module=str(getattr(f, 'module', 'unknown')),
                    risk=RiskLevel(risk_name) if risk_name in RiskLevel._value2member_map_ else RiskLevel.LOW,
                    severity=Severity(sev_name) if sev_name in Severity._value2member_map_ else Severity.LOW,
                    tactic=getattr(f, 'tactic', None),
                    description=str(getattr(f, 'description', '')),
                    evidence=dict(getattr(f, 'evidence', {}) or {}),
                ))
            except Exception as exc:
                logger.debug("Failed to normalize finding: %s", exc)

        risk_map = {"low": 25, "medium": 50, "high": 75, "critical": 100, "info": 10}
        if out_findings:
            score = min(int(sum(risk_map.get(f.risk.value, 10) for f in out_findings) / len(out_findings)), 100)
        else:
            score = 0

        summary = {
            "total": len(out_findings),
            "risk_score": score,
            "critical": sum(1 for f in out_findings if f.risk == RiskLevel.CRITICAL),
            "high": sum(1 for f in out_findings if f.risk == RiskLevel.HIGH),
            "medium": sum(1 for f in out_findings if f.risk == RiskLevel.MEDIUM),
            "low": sum(1 for f in out_findings if f.risk == RiskLevel.LOW),
        }

        scan = _scans.get(scan_id)
        if scan is not None:
            scan.status = "completed"
            scan.end_time = datetime.utcnow()
            scan.findings = out_findings
            scan.summary = summary

        _shared.findings.extend(out_findings)

        logger.info("Scan %s completed: %d findings, score=%d", scan_id, len(out_findings), score)
    except Exception as exc:
        logger.exception("Scan %s failed: %s", scan_id, exc)
        scan = _scans.get(scan_id)
        if scan is not None:
            scan.status = "failed"
            scan.end_time = datetime.utcnow()
            scan.summary = {"total": 0, "risk_score": 0, "error": 1}

@router.post("/", response_model=ScanResponse, summary="Start a new scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks) -> ScanResponse:
    """Start a new security scan (runs in background)."""
    scan_id = str(uuid.uuid4())
    scan = ScanResponse(
        scan_id=scan_id,
        status="in_progress",
        start_time=datetime.utcnow(),
        findings=[],
        summary={"total": 0, "risk_score": 0},
    )
    _scans[scan_id] = scan
    background_tasks.add_task(_run_scan_task, scan_id, request)
    return scan

@router.get("/{scan_id}", response_model=ScanResponse, summary="Get scan status")
async def get_scan(scan_id: str) -> ScanResponse:
    """
    Get the status and results of a scan.
    
    Args:
        scan_id: Scan identifier
        
    Returns:
        Scan response with status and findings
    """
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return _scans[scan_id]

@router.get("/", response_model=List[ScanResponse], summary="List all scans")
async def list_scans(limit: int = 50, offset: int = 0) -> List[ScanResponse]:
    """
    List all scans with pagination.
    
    Args:
        limit: Maximum number of scans to return
        offset: Number of scans to skip
        
    Returns:
        List of scan responses
    """
    scans = list(_scans.values())
    scans.sort(key=lambda x: x.start_time, reverse=True)
    return scans[offset:offset+limit]

@router.delete("/{scan_id}", summary="Delete a scan")
async def delete_scan(scan_id: str) -> dict:
    """
    Delete a scan record.
    
    Args:
        scan_id: Scan identifier
        
    Returns:
        Deletion confirmation
    """
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    del _scans[scan_id]
    return {"message": f"Scan {scan_id} deleted successfully"}
