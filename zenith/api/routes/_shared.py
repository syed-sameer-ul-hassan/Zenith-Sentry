"""Shared in-memory storage across API routes (scans, findings, defense state)."""
from typing import Dict, List
from zenith.api.models import ScanResponse, FindingResponse

scans: Dict[str, ScanResponse] = {}

findings: List[FindingResponse] = []

defense_state: Dict[str, object] = {
    "lockdown_active": False,
    "lockdown_activated_at": None,
    "mitigation_mode": "monitor",                          
    "blocked_ips": [],
    "blocked_processes": [],
}
