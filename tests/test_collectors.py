#!/usr/bin/env python3
"""
Unit tests for collector modules.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestProcessCollector:
    """Test cases for ProcessCollector."""
    
    def test_process_collector_initialization(self):
        """Test ProcessCollector can be initialized."""
        from zenith.collectors import ProcessCollector
        
        collector = ProcessCollector()
        assert collector is not None
    
    @patch('zenith.collectors.psutil')
    def test_collect_processes(self, mock_psutil):
        """Test process collection."""
        from zenith.collectors import ProcessCollector
        
        mock_proc = Mock()
        mock_proc.pid = 1234
        mock_proc.info = {"name": "test", "cmdline": ["test"]}
        mock_psutil.process_iter.return_value = [mock_proc]
        
        collector = ProcessCollector()
        result = collector.collect()
        
        assert isinstance(result, dict)
        assert 1234 in result
    
    @patch('zenith.collectors.psutil')
    def test_collect_handles_no_such_process(self, mock_psutil):
        """Test collector handles NoSuchProcess gracefully."""
        from zenith.collectors import ProcessCollector
        
        mock_psutil.NoSuchProcess = Exception
        mock_psutil.process_iter.side_effect = [
            Mock(pid=1234, info={"name": "test", "cmdline": ["test"]}),
            Exception("Process not found")
        ]
        
        collector = ProcessCollector()
        result = collector.collect()
        
        assert isinstance(result, dict)

class TestNetworkCollector:
    """Test cases for NetworkCollector."""
    
    def test_network_collector_initialization(self):
        """Test NetworkCollector can be initialized."""
        from zenith.collectors import NetworkCollector
        
        collector = NetworkCollector()
        assert collector is not None
    
    @patch('zenith.collectors.psutil')
    def test_collect_connections(self, mock_psutil):
        """Test network connection collection."""
        from zenith.collectors import NetworkCollector
        
        mock_conn = Mock()
        mock_conn.fd = 5
        mock_conn.family = 2
        mock_conn.type = 1
        mock_conn.laddr = ("192.168.1.1", 8080)
        mock_conn.raddr = ("10.0.0.1", 443)
        mock_conn.status = "ESTABLISHED"
        mock_conn.pid = 1234
        mock_psutil.net_connections.return_value = [mock_conn]
        
        collector = NetworkCollector()
        result = collector.collect()
        
        assert isinstance(result, list)
        assert len(result) > 0
    
    @patch('zenith.collectors.psutil')
    def test_collect_handles_access_denied(self, mock_psutil):
        """Test collector handles AccessDenied gracefully."""
        from zenith.collectors import NetworkCollector
        
        mock_psutil.AccessDenied = Exception
        mock_psutil.net_connections.side_effect = Exception("Access denied")
        
        collector = NetworkCollector()
        result = collector.collect()
        
        assert isinstance(result, list)

class TestSystemCollector:
    """Test cases for SystemCollector."""
    
    def test_system_collector_initialization(self):
        """Test SystemCollector can be initialized."""
        from zenith.collectors import SystemCollector
        
        collector = SystemCollector()
        assert collector is not None
    
    @patch('zenith.collectors.os.walk')
    def test_collect_system_files(self, mock_walk):
        """Test system file collection."""
        from zenith.collectors import SystemCollector
        
        mock_walk.return_value = [
            ("/etc/systemd/system", [], ["test.service"]),
        ]
        
        collector = SystemCollector()
        result = collector.collect()
        
        assert isinstance(result, dict)
    
    def test_get_file_info(self, tmp_path):
        """Test _get_file_info method."""
        from zenith.collectors import SystemCollector
        
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        collector = SystemCollector()
        info = collector._get_file_info(str(test_file))
        
        assert "size" in info
        assert "mode" in info
        assert info["size"] > 0
