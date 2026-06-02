"""Shared in-memory storage across API routes (scans, findings, defense state)."""
from typing import Dict, List
from collections import OrderedDict
from zenith.api.models import ScanResponse, FindingResponse

MAX_SCANS = 1000
MAX_FINDINGS = 10000

scans: OrderedDict[str, ScanResponse] = OrderedDict()

findings: List[FindingResponse] = []

defense_state: Dict[str, object] = {
    "lockdown_active": False,
    "lockdown_activated_at": None,
    "mitigation_mode": "monitor",
    "blocked_ips": [],
    "blocked_processes": [],
}

def add_scan(scan_id: str, scan: ScanResponse) -> None:
    """Add a scan with LRU eviction."""
    scans[scan_id] = scan
    while len(scans) > MAX_SCANS:
        scans.popitem(last=False)

def add_findings(new_findings: List[FindingResponse]) -> None:
    """Add findings with total limit enforcement."""
    global findings
    findings.extend(new_findings)
    if len(findings) > MAX_FINDINGS:
        findings = findings[-MAX_FINDINGS:]
