#!/usr/bin/env python3
"""
Pytest configuration and fixtures for Zenith-Sentry tests.
"""
import os
import sys
import pytest
from typing import Dict, Any
from unittest.mock import Mock, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

@pytest.fixture
def sample_config() -> Dict[str, Any]:
    """Provide a sample configuration for testing."""
    return {
        "suspicious_ports": [1337, 4444, 5555],
        "scan_dirs": ["/etc/systemd/system", "/etc/cron.d"],
        "critical_bins": ["nc", "ncat", "nmap", "socat"],
        "suspicious_paths": ["/tmp/", "/dev/shm/", "/var/tmp/"],
        "mitigation": {
            "safe_mode": True,
            "kill_pid": True,
            "block_ip": True
        }
    }

@pytest.fixture
def mock_process_info() -> Dict[str, Any]:
    """Provide mock process information."""
    return {
        "pid": 1234,
        "name": "test_process",
        "cmdline": ["python", "test.py"]
    }

@pytest.fixture
def mock_network_connection() -> Dict[str, Any]:
    """Provide mock network connection information."""
    return {
        "fd": 5,
        "family": 2,
        "type": 1,
        "laddr_ip": "192.168.1.1",
        "laddr_port": 8080,
        "raddr_ip": "10.0.0.1",
        "raddr_port": 443,
        "status": "ESTABLISHED",
        "pid": 1234
    }

@pytest.fixture
def mock_ebpf_event() -> Dict[str, Any]:
    """Provide mock eBPF event data."""
    return {
        "type": "EXECVE_ENTER",
        "timestamp": 1234567890.123,
        "pid": 1234,
        "uid": 0,
        "comm": "test_process",
        "binary": "/usr/bin/test",
        "filename": "/usr/bin/test",
        "argv": ["test", "arg1", "arg2"]
    }

@pytest.fixture
def mock_bpf():
    """Mock BPF object for eBPF tests."""
    bpf = Mock()
    bpf.perf_buffer_poll = Mock(return_value=None)
    return bpf

@pytest.fixture
def sample_finding():
    """Provide a sample Finding object for testing."""
    from zenith.core import Finding, RiskLevel, Severity
    
    return Finding(
        id="test-001",
        module="test_module",
        risk=RiskLevel.HIGH,
        severity=Severity.HIGH,
        tactic="TA0001",
        description="Test finding description",
        evidence={"key": "value"}
    )

@pytest.fixture
def temp_config_file(tmp_path):
    """Create a temporary config file for testing."""
    import yaml
    
    config_file = tmp_path / "test_config.yaml"
    config_data = {
        "suspicious_ports": [1337, 4444],
        "critical_bins": ["nc", "nmap"],
        "mitigation": {
            "safe_mode": True,
            "kill_pid": True
        }
    }
    
    with open(config_file, 'w') as f:
        yaml.dump(config_data, f)
    
    return str(config_file)

@pytest.fixture
def mock_collectors():
    """Mock collector instances."""
    from unittest.mock import Mock
    
    process_collector = Mock()
    process_collector.collect.return_value = {}
    
    network_collector = Mock()
    network_collector.collect.return_value = []
    
    system_collector = Mock()
    system_collector.collect.return_value = {}
    
    return {
        "process": process_collector,
        "network": network_collector,
        "system": system_collector
    }

def pytest_configure(config):
    """Configure pytest with custom settings."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "security: marks tests as security tests"
    )

def pytest_collection_modifyitems(config, items):
    """Skip tests that require root if not running as root."""
    if os.geteuid() != 0:
        skip_root = pytest.mark.skip(reason="Test requires root privileges")
        for item in items:
            if "root" in item.keywords:
                item.add_marker(skip_root)
