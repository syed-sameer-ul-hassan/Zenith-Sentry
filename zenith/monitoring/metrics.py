#!/usr/bin/env python3
"""
Prometheus metrics for Zenith-Sentry.
Exposes metrics for scans, events, and system resources.
"""
from prometheus_client import Counter, Gauge, Histogram, Info
from prometheus_client.core import REGISTRY
import logging

logger = logging.getLogger(__name__)

scans_total = Counter(
    'zenith_scans_total',
    'Total number of scans performed',
    ['scan_type', 'status']
)

scans_duration = Histogram(
    'zenith_scan_duration_seconds',
    'Scan duration in seconds',
    ['scan_type'],
    buckets=[1, 5, 10, 30, 60, 120, 300, 600]
)

findings_total = Counter(
    'zenith_findings_total',
    'Total number of findings',
    ['risk_level', 'severity', 'module']
)

findings_by_tactic = Counter(
    'zenith_findings_by_tactic',
    'Findings by MITRE ATT&CK tactic',
    ['tactic']
)

events_total = Counter(
    'zenith_events_total',
    'Total number of security events',
    ['event_type', 'severity']
)

events_rate = Histogram(
    'zenith_events_rate',
    'Events per time window',
    buckets=[1, 5, 10, 20, 50, 100, 200, 500]
)

mitigations_total = Counter(
    'zenith_mitigations_total',
    'Total number of mitigation actions',
    ['action_type', 'status']
)

system_cpu_usage = Gauge(
    'zenith_system_cpu_usage_percent',
    'CPU usage percentage'
)

system_memory_usage = Gauge(
    'zenith_system_memory_usage_bytes',
    'Memory usage in bytes'
)

system_disk_usage = Gauge(
    'zenith_system_disk_usage_bytes',
    'Disk usage in bytes'
)

active_connections = Gauge(
    'zenith_active_connections',
    'Number of active network connections'
)

ebpf_events_total = Counter(
    'zenith_ebpf_events_total',
    'Total number of eBPF events',
    ['event_type']
)

ebpf_event_rate = Histogram(
    'zenith_ebpf_event_rate',
    'eBPF events per time window',
    buckets=[10, 50, 100, 500, 1000, 5000, 10000]
)

api_requests_total = Counter(
    'zenith_api_requests_total',
    'Total API requests',
    ['endpoint', 'method', 'status']
)

api_request_duration = Histogram(
    'zenith_api_request_duration_seconds',
    'API request duration',
    ['endpoint'],
    buckets=[0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10]
)

app_info = Info(
    'zenith_sentry_info',
    'Zenith-Sentry application information'
)

def record_scan(scan_type: str, status: str, duration: float) -> None:
    """
    Record a scan metric.
    
    Args:
        scan_type: Type of scan performed
        status: Scan status
        duration: Scan duration in seconds
    """
    scans_total.labels(scan_type=scan_type, status=status).inc()
    scans_duration.labels(scan_type=scan_type).observe(duration)

def record_finding(risk_level: str, severity: str, module: str, tactic: str = None) -> None:
    """
    Record a finding metric.
    
    Args:
        risk_level: Risk level of finding
        severity: Severity level of finding
        module: Module that generated the finding
        tactic: MITRE ATT&CK tactic
    """
    findings_total.labels(risk_level=risk_level, severity=severity, module=module).inc()
    if tactic:
        findings_by_tactic.labels(tactic=tactic).inc()

def record_event(event_type: str, severity: str) -> None:
    """
    Record a security event metric.
    
    Args:
        event_type: Type of security event
        severity: Severity level
    """
    events_total.labels(event_type=event_type, severity=severity).inc()
    events_rate.observe()

def record_mitigation(action_type: str, status: str) -> None:
    """
    Record a mitigation action metric.
    
    Args:
        action_type: Type of mitigation action
        status: Status of mitigation
    """
    mitigations_total.labels(action_type=action_type, status=status).inc()

def update_system_metrics(cpu_percent: float, memory_bytes: int, disk_bytes: int) -> None:
    """
    Update system resource metrics.
    
    Args:
        cpu_percent: CPU usage percentage
        memory_bytes: Memory usage in bytes
        disk_bytes: Disk usage in bytes
    """
    system_cpu_usage.set(cpu_percent)
    system_memory_usage.set(memory_bytes)
    system_disk_usage.set(disk_bytes)

def update_connection_count(count: int) -> None:
    """
    Update active connection count.
    
    Args:
        count: Number of active connections
    """
    active_connections.set(count)

def record_ebpf_event(event_type: str) -> None:
    """
    Record an eBPF event metric.
    
    Args:
        event_type: Type of eBPF event
    """
    ebpf_events_total.labels(event_type=event_type).inc()
    ebpf_event_rate.observe()

def record_api_request(endpoint: str, method: str, status: str, duration: float) -> None:
    """
    Record an API request metric.
    
    Args:
        endpoint: API endpoint
        method: HTTP method
        status: Response status code
        duration: Request duration in seconds
    """
    api_requests_total.labels(endpoint=endpoint, method=method, status=status).inc()
    api_request_duration.labels(endpoint=endpoint).observe(duration)

def update_app_info(version: str, commit: str = None, build_date: str = None) -> None:
    """
    Update application information.
    
    Args:
        version: Application version
        commit: Git commit hash
        build_date: Build date
    """
    info = {
        'version': version
    }
    if commit:
        info['commit'] = commit
    if build_date:
        info['build_date'] = build_date
    
    app_info.info(info)
