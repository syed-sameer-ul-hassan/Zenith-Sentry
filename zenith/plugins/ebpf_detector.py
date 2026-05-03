                                                                                          
import logging
import os
import json
from typing import List, Optional, Dict, Any
from zenith.core import IDetector, Finding, RiskLevel, Severity
logger = logging.getLogger(__name__)
class EBPFExecutionDetector(IDetector):
    name = "EBPFKernelMonitor"
    DEFAULT_CRITICAL_PORTS  = {1337, 4444, 5555}
    DEFAULT_CRITICAL_BINS   = {"nc", "ncat", "nmap", "socat"}
    DEFAULT_SUSPICIOUS_PATHS = ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"]
    def __init__(self, ebpf_events: Optional[List[Dict[str, Any]]] = None,
                 config: dict = None, **kwargs):
        self.ebpf_events = ebpf_events or []
        self.config      = config or {}
        self.critical_ports   = set(self.config.get("critical_ports",   list(self.DEFAULT_CRITICAL_PORTS)))
        self.critical_bins    = set(self.config.get("critical_bins",    list(self.DEFAULT_CRITICAL_BINS)))
        self.suspicious_paths = list(self.config.get("suspicious_paths", self.DEFAULT_SUSPICIOUS_PATHS))
    def analyze(self) -> List[Finding]:
        findings: List[Finding] = []
        if not self.ebpf_events:
            return findings
        for event in self.ebpf_events:
            etype = event.get("type", event.get("event_type", "")).upper()
            if etype in ("EXECVE_ENTER", "EXECVE_FAILED"):
                findings.extend(self._analyze_execve(event, etype))
            elif etype == "TCP_CONNECT":
                findings.extend(self._analyze_connect(event))
        logger.info(f"EBPFKernelMonitor produced {len(findings)} findings")
        return findings
    def _analyze_execve(self, event: Dict[str, Any], etype: str) -> List[Finding]:
        findings: List[Finding] = []
        proc      = event.get("process", {})
        binary    = event.get("binary", event.get("execution", {}).get("binary", ""))
        basename  = os.path.basename(binary)
        pid       = proc.get("pid")
        uid       = proc.get("uid", proc.get("uid"))
        name      = proc.get("name", "unknown")
        timestamp = event.get("timestamp")
        if basename in self.critical_bins:
            findings.append(Finding(
                module=self.name,
                risk=RiskLevel.CRITICAL,
                severity=Severity.CRITICAL,
                tactic="Execution",
                description=f"Critical binary executed: {binary} (watchlist match)",
                evidence={"pid": pid, "uid": uid, "binary": binary,
                          "timestamp": timestamp}
            ))
        if uid == 0 and name:
            findings.append(Finding(
                module=self.name,
                risk=RiskLevel.HIGH,
                severity=Severity.HIGH,
                tactic="Privilege Escalation",
                description=f"Root-level process execution: {name} ({binary})",
                evidence={"pid": pid, "uid": uid, "binary": binary,
                          "timestamp": timestamp}
            ))
        if any(binary.startswith(p) for p in self.suspicious_paths):
            findings.append(Finding(
                module=self.name,
                risk=RiskLevel.CRITICAL,
                severity=Severity.CRITICAL,
                tactic="Execution",
                description=f"Binary executed from suspicious location: {binary}",
                evidence={"pid": pid, "binary": binary, "timestamp": timestamp}
            ))
        if etype == "EXECVE_FAILED":
            findings.append(Finding(
                module=self.name,
                risk=RiskLevel.MEDIUM,
                severity=Severity.MEDIUM,
                tactic="Defense Evasion",
                description=f"Execve failure detected for: {binary}",
                evidence={"pid": pid, "binary": binary, "timestamp": timestamp,
                          "event_type": etype}
            ))
        return findings
    def _analyze_connect(self, event: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        proc      = event.get("process", {})
        dest      = event.get("destination", {})
        pid       = proc.get("pid")
        uid       = proc.get("uid")
        ip        = dest.get("ip", "unknown")
        port      = dest.get("port", 0)
        timestamp = event.get("timestamp")
        if port in self.critical_ports:
            findings.append(Finding(
                module=self.name,
                risk=RiskLevel.CRITICAL,
                severity=Severity.CRITICAL,
                tactic="Command and Control",
                description=f"Outbound connection to critical port {port} at {ip}",
                evidence={"pid": pid, "uid": uid, "ip": ip, "port": port,
                          "timestamp": timestamp}
            ))
        if 31337 <= port <= 31340 or port in {6666, 6667, 9999}:
            findings.append(Finding(
                module=self.name,
                risk=RiskLevel.HIGH,
                severity=Severity.HIGH,
                tactic="Command and Control",
                description=f"Connection to suspicious port {port} at {ip}",
                evidence={"pid": pid, "uid": uid, "ip": ip, "port": port,
                          "timestamp": timestamp}
            ))
        return findings
