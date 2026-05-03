#!/usr/bin/env python3
"""
Health check endpoints for Zenith-Sentry.
Provides comprehensive health status for the application.
"""
from datetime import datetime, timedelta
from typing import Dict, Any, List
import psutil
import logging

logger = logging.getLogger(__name__)

class HealthCheck:
    """Health check class for monitoring system health."""
    
    def __init__(self):
        self.start_time = datetime.utcnow()
        self.last_check_time = None
        self.checks: Dict[str, Any] = {}
    
    def check_database(self) -> Dict[str, Any]:
        """
        Check database connectivity.
        
        Returns:
            Health check result
        """
        try:
            from zenith.db.base import get_engine
            engine = get_engine()
            
            with engine.connect() as conn:
                conn.execute("SELECT 1")
            
            return {
                "status": "healthy",
                "message": "Database connection successful"
            }
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                "status": "unhealthy",
                "message": f"Database connection failed: {str(e)}"
            }
    
    def check_filesystem(self) -> Dict[str, Any]:
        """
        Check filesystem health.
        
        Returns:
            Health check result
        """
        try:
            disk = psutil.disk_usage('/')
            free_percent = (disk.free / disk.total) * 100
            
            if free_percent < 10:
                return {
                    "status": "unhealthy",
                    "message": f"Low disk space: {free_percent:.1f}% free"
                }
            
            return {
                "status": "healthy",
                "message": f"Disk space OK: {free_percent:.1f}% free"
            }
        except Exception as e:
            logger.error(f"Filesystem health check failed: {e}")
            return {
                "status": "unhealthy",
                "message": f"Filesystem check failed: {str(e)}"
            }
    
    def check_memory(self) -> Dict[str, Any]:
        """
        Check memory usage.
        
        Returns:
            Health check result
        """
        try:
            memory = psutil.virtual_memory()
            used_percent = memory.percent
            
            if used_percent > 90:
                return {
                    "status": "unhealthy",
                    "message": f"High memory usage: {used_percent:.1f}%"
                }
            
            return {
                "status": "healthy",
                "message": f"Memory usage OK: {used_percent:.1f}%"
            }
        except Exception as e:
            logger.error(f"Memory health check failed: {e}")
            return {
                "status": "unhealthy",
                "message": f"Memory check failed: {str(e)}"
            }
    
    def check_cpu(self) -> Dict[str, Any]:
        """
        Check CPU usage.
        
        Returns:
            Health check result
        """
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            
            if cpu_percent > 90:
                return {
                    "status": "unhealthy",
                    "message": f"High CPU usage: {cpu_percent:.1f}%"
                }
            
            return {
                "status": "healthy",
                "message": f"CPU usage OK: {cpu_percent:.1f}%"
            }
        except Exception as e:
            logger.error(f"CPU health check failed: {e}")
            return {
                "status": "unhealthy",
                "message": f"CPU check failed: {str(e)}"
            }
    
    def check_ebpf(self) -> Dict[str, Any]:
        """
        Check eBPF module availability.
        
        Returns:
            Health check result
        """
        try:
            import bcc
            return {
                "status": "healthy",
                "message": "eBPF module available"
            }
        except ImportError:
            return {
                "status": "degraded",
                "message": "eBPF module not available (BCC not installed)"
            }
        except Exception as e:
            logger.error(f"eBPF health check failed: {e}")
            return {
                "status": "unhealthy",
                "message": f"eBPF check failed: {str(e)}"
            }
    
    def run_all_checks(self) -> Dict[str, Any]:
        """
        Run all health checks.
        
        Returns:
            Overall health status
        """
        self.last_check_time = datetime.utcnow()
        
        checks = {
            "database": self.check_database(),
            "filesystem": self.check_filesystem(),
            "memory": self.check_memory(),
            "cpu": self.check_cpu(),
            "ebpf": self.check_ebpf()
        }
        
        self.checks = checks
        
        unhealthy_count = sum(1 for check in checks.values() if check["status"] == "unhealthy")
        degraded_count = sum(1 for check in checks.values() if check["status"] == "degraded")
        
        if unhealthy_count > 0:
            overall_status = "unhealthy"
        elif degraded_count > 0:
            overall_status = "degraded"
        else:
            overall_status = "healthy"
        
        uptime = (datetime.utcnow() - self.start_time).total_seconds()
        
        return {
            "status": overall_status,
            "uptime_seconds": uptime,
            "timestamp": self.last_check_time.isoformat(),
            "checks": checks,
            "summary": {
                "total": len(checks),
                "healthy": len([c for c in checks.values() if c["status"] == "healthy"]),
                "degraded": degraded_count,
                "unhealthy": unhealthy_count
            }
        }
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get current health status without running checks.
        
        Returns:
            Cached health status
        """
        if not self.checks:
            return self.run_all_checks()
        
        uptime = (datetime.utcnow() - self.start_time).total_seconds()
        
        return {
            "status": "cached",
            "uptime_seconds": uptime,
            "timestamp": self.last_check_time.isoformat(),
            "checks": self.checks
        }

_health_check: HealthCheck = None

def get_health_check() -> HealthCheck:
    """Get the global health check instance."""
    global _health_check
    if _health_check is None:
        _health_check = HealthCheck()
    return _health_check
