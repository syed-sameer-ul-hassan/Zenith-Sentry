"""System telemetry collectors for Zenith-Sentry EDR."""

import psutil
import logging

logger = logging.getLogger(__name__)


class ProcessCollector:
    """Collects process telemetry from /proc."""
    
    def collect(self):
        """Enumerate all running processes with full details.
        
        Returns:
            dict: {pid: {'pid': int, 'name': str, 'cmdline': list}}
        """
        procs = {}
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    procs[proc.pid] = proc.info
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    logger.warning(f"Error reading process {proc.pid}: {type(e).__name__}")
                    continue
        except Exception as e:
            logger.error(f"Process enumeration failed: {e}")
        
        return procs


class NetworkCollector:
    """Collects network connection telemetry."""
    
    def collect(self):
        """Enumerate all active network connections.
        
        Returns:
            list: Empty for now (extensible placeholder)
        """
        return []


class SystemCollector:
    """Collects filesystem and system telemetry."""
    
    def __init__(self, scan_dirs):
        """Initialize system collector.
        
        Args:
            scan_dirs: List of directories to scan for persistence indicators
        """
        self.scan_dirs = scan_dirs or []
    
    def collect(self):
        """Scan directories for persistence indicators.
        
        Returns:
            dict: Empty for now (extensible placeholder)
        """
        return {}

