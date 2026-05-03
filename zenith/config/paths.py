#!/usr/bin/env python3
"""
Path configuration module for Zenith-Sentry.
Provides FHS-compliant paths and XDG config support.
"""
import os
from pathlib import Path
from typing import Optional
from xdg import BaseDirectory

class PathConfig:
    """
    Manages all file paths for Zenith-Sentry.
    Uses FHS (Filesystem Hierarchy Standard) compliant paths.
    """
    
    CONFIG_DIR = "/etc/zenith-sentry"
    DATA_DIR = "/var/lib/zenith-sentry"
    LOG_DIR = "/var/log/zenith-sentry"
    RUN_DIR = "/var/run/zenith-sentry"
    
    DEFAULT_CONFIG_FILE = "config.yaml"
    
    USER_DATA_DIR = os.path.expanduser("~/user_data")
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize path configuration.
        
        Args:
            config_file: Optional custom config file path
        """
        self.config_file = config_file or self._get_config_path()
        self.data_dir = self._get_data_dir()
        self.log_dir = self._get_log_dir()
        self.report_dir = os.path.join(self.data_dir, "reports")
        self.ebpf_source = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ebpf", "execve_monitor.c")
        
        self._ensure_directories()
    
    def _get_config_path(self) -> str:
        """
        Get the config file path.
        Checks XDG config directory first, then falls back to FHS.
        
        Returns:
            Path to config file
        """
                                  
        try:
            xdg_config = os.path.join(BaseDirectory.xdg_config_home, "zenith-sentry")
            xdg_config_file = os.path.join(xdg_config, self.DEFAULT_CONFIG_FILE)
            if os.path.exists(xdg_config_file):
                return xdg_config_file
        except (ImportError, AttributeError):
            pass
        
        fhs_config = os.path.join(self.CONFIG_DIR, self.DEFAULT_CONFIG_FILE)
        if os.path.exists(fhs_config):
            return fhs_config
        
        local_config = os.path.join(os.path.dirname(os.path.dirname(__file__)), self.DEFAULT_CONFIG_FILE)
        if os.path.exists(local_config):
            return local_config
        
        return fhs_config
    
    def _get_data_dir(self) -> str:
        """
        Get the data directory path.
        Uses XDG data directory if available, otherwise FHS.
        
        Returns:
            Path to data directory
        """
        try:
            return os.path.join(BaseDirectory.xdg_data_home, "zenith-sentry")
        except (ImportError, AttributeError):
            return self.DATA_DIR
    
    def _get_log_dir(self) -> str:
        """
        Get the log directory path.
        Uses XDG data directory if available, otherwise FHS.
        
        Returns:
            Path to log directory
        """
        try:
            return os.path.join(BaseDirectory.xdg_data_home, "zenith-sentry", "logs")
        except (ImportError, AttributeError):
            return self.LOG_DIR
    
    def _ensure_directories(self) -> None:
        """Ensure all required directories exist."""
        directories = [
            self.data_dir,
            self.log_dir,
            self.report_dir,
            self.USER_DATA_DIR
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
            except (PermissionError, OSError) as e:
                                            
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Could not create directory {directory}: {e}")
    
    def get_ebpf_source_path(self) -> str:
        """
        Get the path to the eBPF source file.
        
        Returns:
            Path to eBPF source file
        """
        return self.ebpf_source
    
    def get_report_path(self, name: str) -> str:
        """
        Get the path for a report file.
        
        Args:
            name: Name of the report file
            
        Returns:
            Full path to the report file
        """
        return os.path.join(self.report_dir, name)
    
    def get_log_path(self, name: str) -> str:
        """
        Get the path for a log file.
        
        Args:
            name: Name of the log file
            
        Returns:
            Full path to the log file
        """
        return os.path.join(self.log_dir, name)

_path_config: Optional[PathConfig] = None

def get_path_config(config_file: Optional[str] = None) -> PathConfig:
    """
    Get the global path configuration instance.
    
    Args:
        config_file: Optional custom config file path
        
    Returns:
        PathConfig instance
    """
    global _path_config
    
    if _path_config is None:
        _path_config = PathConfig(config_file)
    
    return _path_config

def reset_path_config() -> None:
    """Reset the global path configuration instance (useful for testing)."""
    global _path_config
    _path_config = None
