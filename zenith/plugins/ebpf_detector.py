"""eBPF-based kernel execution detector - integrates kernel-level monitoring."""

import logging
import os
import json
from typing import List, Optional, Dict, Any

from zenith.core import IDetector, Finding, RiskLevel, Severity

logger = logging.getLogger(__name__)


class EBPFExecutionDetector(IDetector):
    """Detects suspicious process execution from kernel-level eBPF monitoring.
    
    This detector integrates findings from the eBPF process execution monitor
    into the standard Finding objects for unified risk scoring.
    """
    
    name = "EBPFKernelExecution"
    
    def __init__(self, ebpf_events: Optional[List[Dict[str, Any]]] = None, config: dict = None, **kwargs):
        """Initialize eBPF detector.
        
        Args:
            ebpf_events: List of events from kernel eBPF monitor
            config: Configuration dictionary (optional)
            **kwargs: Unused, for plugin compatibility
        """
        self.ebpf_events = ebpf_events or []
        self.config = config or {}
        
    def analyze(self) -> List[Finding]:
        """Convert eBPF kernel events to Finding objects.
        
        Returns:
            List of Finding objects from kernel-level detections
        """
        findings = []
        
        if not self.ebpf_events:
            return findings
        
        for event in self.ebpf_events:
            if self._is_root_execution(event):
                findings.append(Finding(
                    module=self.name,
                    risk=RiskLevel.HIGH,
                    severity=Severity.HIGH,
                    tactic="Privilege Escalation",
                    description=f"Root-level process execution detected: {event.get('process', {}).get('name', 'unknown')}",
                    evidence={
                        "pid": event.get("process", {}).get("pid"),
                        "uid": event.get("process", {}).get("uid"),
                        "binary": event.get("execution", {}).get("binary"),
                        "timestamp": event.get("timestamp")
                    }
                ))
            
            if self._is_suspicious_location(event):
                binary = event.get("execution", {}).get("binary", "")
                findings.append(Finding(
                    module=self.name,
                    risk=RiskLevel.CRITICAL,
                    severity=Severity.CRITICAL,
                    tactic="Execution",
                    description=f"Binary executed from suspicious location: {binary}",
                    evidence={
                        "pid": event.get("process", {}).get("pid"),
                        "binary": binary,
                        "timestamp": event.get("timestamp")
                    }
                ))
            
            if self._is_evasion_attempt(event):
                findings.append(Finding(
                    module=self.name,
                    risk=RiskLevel.MEDIUM,
                    severity=Severity.MEDIUM,
                    tactic="Defense Evasion",
                    description=f"Execve failure detected: {event.get('execution', {}).get('binary', 'unknown')}",
                    evidence={
                        "pid": event.get("process", {}).get("pid"),
                        "binary": event.get("execution", {}).get("binary"),
                        "timestamp": event.get("timestamp"),
                        "event_type": event.get("event_type")
                    }
                ))
        
        logger.info(f"EBPFExecutionDetector found {len(findings)} kernel-level threats")
        return findings
    
    def _is_root_execution(self, event: Dict[str, Any]) -> bool:
        """Check if process executed as root (non-system).
        
        Args:
            event: eBPF event dictionary
            
        Returns:
            True if suspicious root execution
        """
        if event.get("process", {}).get("uid") != 0:
            return False
        
        comm = event.get("process", {}).get("name", "").lower()
        return len(comm) > 0
    
    def _is_suspicious_location(self, event: Dict[str, Any]) -> bool:
        """Check if binary is in suspicious location.
        
        Args:
            event: eBPF event dictionary
            
        Returns:
            True if binary in suspicious directory
        """
        binary = event.get("execution", {}).get("binary", "").lower()
        
        suspicious_paths = self.config.get("suspicious_paths", [
            "/tmp/", "/dev/shm/", "/var/tmp/"
        ])
        
        return any(binary.startswith(path) for path in suspicious_paths)
    
    def _is_evasion_attempt(self, event: Dict[str, Any]) -> bool:
        """Check if event indicates evasion technique.
        
        Args:
            event: eBPF event dictionary
            
        Returns:
            True if event suggests evasion
        """
        event_type = event.get("event_type", "").upper()
        return event_type == "EXECVE_FAILED"
