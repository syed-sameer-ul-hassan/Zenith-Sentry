#!/usr/bin/env python3
"""
Unit tests for engine module.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestZenithEngine:
    """Test cases for ZenithEngine."""
    
    def test_engine_initialization(self, sample_config, tmp_path):
        """Test ZenithEngine can be initialized."""
        from zenith.engine import ZenithEngine
        from zenith.config import ConfigLoader
        
        import yaml
        config_file = tmp_path / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(sample_config, f)
        
        config = ConfigLoader(str(config_file))
        engine = ZenithEngine(config.config)
        
        assert engine is not None
        assert engine.config.config == sample_config
    
    def test_engine_collects_telemetry(self, sample_config, tmp_path):
        """Test engine collects telemetry from all collectors."""
        from zenith.engine import ZenithEngine
        from zenith.config import ConfigLoader
        import yaml
        
        config_file = tmp_path / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(sample_config, f)
        
        config = ConfigLoader(str(config_file))
        engine = ZenithEngine(config.config)
        
        procs, conns, sys_files = engine._collect_telemetry()
        
        assert isinstance(procs, dict)
        assert isinstance(conns, list)
        assert isinstance(sys_files, dict)
    
    @patch('zenith.engine.Thread')
    def test_engine_starts_ebpf_thread(self, mock_thread, sample_config, tmp_path):
        """Test engine starts eBPF thread when enabled."""
        from zenith.engine import ZenithEngine
        from zenith.config import ConfigLoader
        import yaml
        
        config_file = tmp_path / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(sample_config, f)
        
        config = ConfigLoader(str(config_file))
        engine = ZenithEngine(config.config, ebpf_enabled=True)
        
        assert engine.ebpf_thread is not None or not engine.ebpf_enabled
    
    def test_engine_loads_plugins(self, sample_config, tmp_path):
        """Test engine loads detector plugins."""
        from zenith.engine import ZenithEngine
        from zenith.config import ConfigLoader
        import yaml
        
        config_file = tmp_path / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(sample_config, f)
        
        config = ConfigLoader(str(config_file))
        engine = ZenithEngine(config.config)
        
        detectors = engine.registry.instantiate(
            procs={},
            conns=[],
            sys_files={},
            ebpf_events=[],
            config=config.config
        )
        
        assert isinstance(detectors, list)
    
    @patch('zenith.engine.open')
    def test_engine_generates_report(self, mock_open, sample_config, tmp_path):
        """Test engine generates JSON report."""
        from zenith.engine import ZenithEngine
        from zenith.config import ConfigLoader
        import yaml
        
        config_file = tmp_path / "config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(sample_config, f)
        
        config = ConfigLoader(str(config_file))
        engine = ZenithEngine(config.config)
        
        mock_file = MagicMock()
        mock_open.return_value.__enter__ = Mock(return_value=mock_file)
        mock_open.return_value.__exit__ = Mock(return_value=False)
        
        report_path = os.path.join(tmp_path, "test_report.json")
        engine._generate_report([], 0, report_path)
        
        mock_open.assert_called_once()
