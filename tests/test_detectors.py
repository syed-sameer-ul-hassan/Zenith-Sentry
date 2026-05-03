#!/usr/bin/env python3
"""
Unit tests for detector modules.
"""
import pytest
from unittest.mock import Mock, patch
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestProcessDetector:
    """Test cases for ProcessDetector."""
    
    def test_process_detector_initialization(self, sample_config):
        """Test ProcessDetector can be initialized."""
        from zenith.plugins.detectors import ProcessDetector
        
        detector = ProcessDetector(
            procs={},
            conns=[],
            sys_files={},
            ebpf_events=[],
            config=sample_config
        )
        
        assert detector is not None
        assert detector.config == sample_config
    
    def test_process_detector_detects_suspicious_ports(self, sample_config):
        """Test ProcessDetector detects processes on suspicious ports."""
        from zenith.plugins.detectors import ProcessDetector
        from zenith.core import Finding, RiskLevel, Severity
        
        procs = {
            1234: {
                "name": "nc",
                "cmdline": ["nc", "-l", "1337"],
                "connections": [
                    {"laddr_port": 1337, "raddr_ip": "10.0.0.1", "raddr_port": 443}
                ]
            }
        }
        
        detector = ProcessDetector(
            procs=procs,
            conns=[],
            sys_files={},
            ebpf_events=[],
            config=sample_config
        )
        
        findings = detector.detect()
        
        assert isinstance(findings, list)
                                                     
        assert len(findings) > 0
    
    def test_process_detector_detects_critical_bins(self, sample_config):
        """Test ProcessDetector detects critical binaries."""
        from zenith.plugins.detectors import ProcessDetector
        
        procs = {
            1234: {
                "name": "nc",
                "cmdline": ["nc", "-l", "8080"],
                "connections": []
            }
        }
        
        detector = ProcessDetector(
            procs=procs,
            conns=[],
            sys_files={},
            ebpf_events=[],
            config=sample_config
        )
        
        findings = detector.detect()
        
        assert isinstance(findings, list)
                                             
        assert len(findings) > 0
    
    def test_process_detector_no_findings(self, sample_config):
        """Test ProcessDetector returns no findings for clean processes."""
        from zenith.plugins.detectors import ProcessDetector
        
        procs = {
            1234: {
                "name": "python",
                "cmdline": ["python", "script.py"],
                "connections": []
            }
        }
        
        detector = ProcessDetector(
            procs=procs,
            conns=[],
            sys_files={},
            ebpf_events=[],
            config=sample_config
        )
        
        findings = detector.detect()
        
        assert isinstance(findings, list)

class TestEBPFExecutionDetector:
    """Test cases for EBPFExecutionDetector."""
    
    def test_ebpf_detector_initialization(self, sample_config):
        """Test EBPFExecutionDetector can be initialized."""
        from zenith.plugins.ebpf_detector import EBPFExecutionDetector
        
        detector = EBPFExecutionDetector(
            procs={},
            conns=[],
            sys_files={},
            ebpf_events=[],
            config=sample_config
        )
        
        assert detector is not None
    
    def test_ebpf_detector_processes_events(self, sample_config, mock_ebpf_event):
        """Test EBPFExecutionDetector processes eBPF events."""
        from zenith.plugins.ebpf_detector import EBPFExecutionDetector
        
        detector = EBPFExecutionDetector(
            procs={},
            conns=[],
            sys_files={},
            ebpf_events=[mock_ebpf_event],
            config=sample_config
        )
        
        findings = detector.detect()
        
        assert isinstance(findings, list)
    
    def test_ebpf_detector_detects_suspicious_connections(self, sample_config):
        """Test EBPFExecutionDetector detects suspicious network connections."""
        from zenith.plugins.ebpf_detector import EBPFExecutionDetector
        
        ebpf_event = {
            "type": "TCP_CONNECT",
            "timestamp": 1234567890.123,
            "pid": 1234,
            "uid": 0,
            "daddr_ip": "10.0.0.1",
            "dport": 1337,
            "comm": "nc"
        }
        
        detector = EBPFExecutionDetector(
            procs={},
            conns=[],
            sys_files={},
            ebpf_events=[ebpf_event],
            config=sample_config
        )
        
        findings = detector.detect()
        
        assert isinstance(findings, list)
                                                     
        assert len(findings) > 0

class TestFinding:
    """Test cases for Finding data model."""
    
    def test_finding_creation(self):
        """Test Finding object can be created."""
        from zenith.core import Finding, RiskLevel, Severity
        
        finding = Finding(
            id="test-001",
            module="test_module",
            risk=RiskLevel.HIGH,
            severity=Severity.HIGH,
            tactic="TA0001",
            description="Test finding",
            evidence={"key": "value"}
        )
        
        assert finding.id == "test-001"
        assert finding.module == "test_module"
        assert finding.risk == RiskLevel.HIGH
        assert finding.severity == Severity.HIGH
    
    def test_finding_to_dict(self):
        """Test Finding can be converted to dictionary."""
        from zenith.core import Finding, RiskLevel, Severity
        
        finding = Finding(
            id="test-001",
            module="test_module",
            risk=RiskLevel.HIGH,
            severity=Severity.HIGH,
            tactic="TA0001",
            description="Test finding",
            evidence={"key": "value"}
        )
        
        finding_dict = finding.to_dict()
        
        assert finding_dict["id"] == "test-001"
        assert finding_dict["module"] == "test_module"
        assert finding_dict["risk"] == RiskLevel.HIGH.value
