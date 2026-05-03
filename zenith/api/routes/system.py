#!/usr/bin/env python3
"""
System-related API routes.
"""
from fastapi import APIRouter
from typing import Dict, Any
import platform
import psutil

router = APIRouter()

@router.get("/info", summary="Get system information")
async def get_system_info() -> Dict[str, Any]:
    """
    Get system information including OS, kernel, and hardware details.
    
    Returns:
        Dictionary with system information
    """
    return {
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor()
        },
        "kernel": platform.version(),
        "hostname": platform.node(),
        "architecture": platform.machine()
    }

@router.get("/resources", summary="Get system resource usage")
async def get_system_resources() -> Dict[str, Any]:
    """
    Get current system resource usage (CPU, memory, disk).
    
    Returns:
        Dictionary with resource usage information
    """
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return {
        "cpu": {
            "percent": cpu_percent,
            "count": psutil.cpu_count()
        },
        "memory": {
            "total": memory.total,
            "available": memory.available,
            "used": memory.used,
            "percent": memory.percent
        },
        "disk": {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent
        }
    }

@router.get("/processes", summary="Get running processes")
async def get_processes(limit: int = 50) -> Dict[str, Any]:
    """
    Get list of running processes.
    
    Args:
        limit: Maximum number of processes to return
        
    Returns:
        Dictionary with process information
    """
    processes = []
    count = 0
    
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
        if count >= limit:
            break
        try:
            processes.append({
                "pid": proc.info['pid'],
                "name": proc.info['name'],
                "username": proc.info['username'],
                "cmdline": proc.info['cmdline']
            })
            count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    return {
        "total": len(list(psutil.process_iter())),
        "processes": processes
    }

@router.get("/network", summary="Get network connections")
async def get_network_connections() -> Dict[str, Any]:
    """
    Get active network connections.
    
    Returns:
        Dictionary with network connection information
    """
    connections = []
    
    try:
        for conn in psutil.net_connections(kind='inet'):
            try:
                connections.append({
                    "fd": conn.fd,
                    "family": conn.family,
                    "type": conn.type,
                    "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except psutil.AccessDenied:
        pass
    
    return {
        "total": len(connections),
        "connections": connections
    }

@router.get("/config", summary="Get active configuration")
async def get_config() -> Dict[str, Any]:
    """Return the currently loaded Zenith-Sentry configuration (sanitized)."""
    try:
        from zenith.config import ConfigLoader
        cfg = ConfigLoader(None).config or {}
    except Exception:
        cfg = {}

    return {
        "network": {
            "suspicious_ports": (cfg.get("network", {}) or {}).get("suspicious_ports", []),
            "ignore_loopback": (cfg.get("network", {}) or {}).get("ignore_loopback", True),
        },
        "persistence": {
            "scan_dirs": (cfg.get("persistence", {}) or {}).get("scan_dirs", []),
        },
        "ebpf": {
            "critical_ports": (cfg.get("ebpf", {}) or {}).get("critical_ports", []),
            "critical_bins": (cfg.get("ebpf", {}) or {}).get("critical_bins", []),
            "suspicious_paths": (cfg.get("ebpf", {}) or {}).get("suspicious_paths", []),
            "mitigation": (cfg.get("ebpf", {}) or {}).get("mitigation", {
                "safe_mode": True, "kill_pid": False, "block_ip": False,
            }),
        },
    }
