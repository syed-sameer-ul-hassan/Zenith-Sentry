#!/usr/bin/env python3
"""
Security event logging for detecting malicious behavior and security incidents.
Logs security events separately from regular logs for correlation and analysis.
"""
import logging
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum
from threading import Lock

logger = logging.getLogger(__name__)

class SecurityEventType(Enum):
    """Types of security events."""
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    PERMISSION_DENIED = "permission_denied"
    CONFIG_CHANGE = "config_change"
    PLUGIN_LOAD = "plugin_load"
    PLUGIN_ERROR = "plugin_error"
    MITIGATION_ACTION = "mitigation_action"
    THREAT_DETECTED = "threat_detected"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    INTEGRITY_FAILURE = "integrity_failure"
    ANOMALY_DETECTED = "anomaly_detected"

class SecuritySeverity(Enum):
    """Severity levels for security events."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityEvent:
    """Represents a security event."""
    
    def __init__(
        self,
        event_type: SecurityEventType,
        severity: SecuritySeverity,
        description: str,
        source: str,
        evidence: Optional[Dict[str, Any]] = None,
        timestamp: Optional[float] = None
    ):
        """
        Initialize a security event.
        
        Args:
            event_type: Type of security event
            severity: Severity level
            description: Event description
            source: Source of the event (component, module, etc.)
            evidence: Evidence data related to the event
            timestamp: Unix timestamp (default: current time)
        """
        self.event_type = event_type
        self.severity = severity
        self.description = description
        self.source = source
        self.evidence = evidence or {}
        self.timestamp = timestamp or time.time()
        self.event_id = self._generate_event_id()
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        return f"{self.event_type.value}_{int(self.timestamp)}_{hash(self.description)}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for logging."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "description": self.description,
            "source": self.source,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "iso_timestamp": datetime.fromtimestamp(self.timestamp).isoformat()
        }

class SecurityEventLogger:
    """
    Logs security events separately from regular application logs.
    Provides correlation and analysis capabilities for security incidents.
    """
    
    def __init__(self, log_file: str = "/var/log/zenith-sentry/security.log"):
        """
        Initialize security event logger.
        
        Args:
            log_file: Path to security log file
        """
        self.log_file = log_file
        self.events: List[SecurityEvent] = []
        self._lock = Lock()
        self._setup_logger()
    
    def _setup_logger(self) -> None:
        """Setup security logger with structured logging."""
        self.security_logger = logging.getLogger('zenith.security')
        self.security_logger.setLevel(logging.INFO)
        
        self.security_logger.propagate = False
        
        try:
            handler = logging.FileHandler(self.log_file)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.security_logger.addHandler(handler)
        except Exception as e:
            logger.warning(f"Could not setup security log file: {e}")
                                          
            self.security_logger.addHandler(logging.StreamHandler())
    
    def log_event(self, event: SecurityEvent) -> None:
        """
        Log a security event.
        
        Args:
            event: Security event to log
        """
        with self._lock:
                                                   
            self.events.append(event)
            
            if len(self.events) > 1000:
                self.events.pop(0)
            
            event_dict = event.to_dict()
            self.security_logger.info(json.dumps(event_dict))
            
            logger.info(f"Security Event [{event.severity.value.upper()}]: {event.description}")
    
    def log_threat_detected(
        self,
        description: str,
        source: str,
        evidence: Optional[Dict[str, Any]] = None,
        severity: SecuritySeverity = SecuritySeverity.HIGH
    ) -> None:
        """
        Log a threat detection event.
        
        Args:
            description: Threat description
            source: Source of threat detection
            evidence: Evidence data
            severity: Threat severity (default: HIGH)
        """
        event = SecurityEvent(
            event_type=SecurityEventType.THREAT_DETECTED,
            severity=severity,
            description=description,
            source=source,
            evidence=evidence
        )
        self.log_event(event)
    
    def log_mitigation_action(
        self,
        action: str,
        target: str,
        reason: str,
        source: str
    ) -> None:
        """
        Log a mitigation action.
        
        Args:
            action: Action taken (e.g., "kill_process", "block_ip")
            target: Target of action (e.g., PID, IP address)
            reason: Reason for mitigation
            source: Source of mitigation
        """
        event = SecurityEvent(
            event_type=SecurityEventType.MITIGATION_ACTION,
            severity=SecuritySeverity.HIGH,
            description=f"Mitigation action: {action} on {target} - {reason}",
            source=source,
            evidence={"action": action, "target": target, "reason": reason}
        )
        self.log_event(event)
    
    def log_auth_failure(
        self,
        user: str,
        method: str,
        reason: str,
        source: str
    ) -> None:
        """
        Log an authentication failure.
        
        Args:
            user: Username or identifier
            method: Auth method (e.g., "api_key", "password")
            reason: Failure reason
            source: Source of auth attempt
        """
        event = SecurityEvent(
            event_type=SecurityEventType.AUTH_FAILURE,
            severity=SecuritySeverity.MEDIUM,
            description=f"Auth failure for {user} via {method}: {reason}",
            source=source,
            evidence={"user": user, "method": method, "reason": reason}
        )
        self.log_event(event)
    
    def log_permission_denied(
        self,
        user: str,
        resource: str,
        action: str,
        source: str
    ) -> None:
        """
        Log a permission denied event.
        
        Args:
            user: User attempting action
            resource: Resource being accessed
            action: Action attempted
            source: Source of request
        """
        event = SecurityEvent(
            event_type=SecurityEventType.PERMISSION_DENIED,
            severity=SecuritySeverity.MEDIUM,
            description=f"Permission denied: {user} attempted {action} on {resource}",
            source=source,
            evidence={"user": user, "resource": resource, "action": action}
        )
        self.log_event(event)
    
    def log_integrity_failure(
        self,
        resource: str,
        expected_hash: str,
        actual_hash: str,
        source: str
    ) -> None:
        """
        Log an integrity failure.
        
        Args:
            resource: Resource with integrity issue
            expected_hash: Expected hash
            actual_hash: Actual hash
            source: Source of integrity check
        """
        event = SecurityEvent(
            event_type=SecurityEventType.INTEGRITY_FAILURE,
            severity=SecuritySeverity.CRITICAL,
            description=f"Integrity failure for {resource}: hash mismatch",
            source=source,
            evidence={
                "resource": resource,
                "expected_hash": expected_hash,
                "actual_hash": actual_hash
            }
        )
        self.log_event(event)
    
    def get_events(
        self,
        event_type: Optional[SecurityEventType] = None,
        severity: Optional[SecuritySeverity] = None,
        since: Optional[float] = None,
        limit: int = 100
    ) -> List[SecurityEvent]:
        """
        Retrieve security events with optional filtering.
        
        Args:
            event_type: Filter by event type
            severity: Filter by severity
            since: Filter events since timestamp
            limit: Maximum number of events to return
            
        Returns:
            List of matching security events
        """
        with self._lock:
            filtered = self.events
            
            if event_type:
                filtered = [e for e in filtered if e.event_type == event_type]
            
            if severity:
                filtered = [e for e in filtered if e.severity == severity]
            
            if since:
                filtered = [e for e in filtered if e.timestamp >= since]
            
            filtered.reverse()
            return filtered[:limit]
    
    def get_critical_events(self, hours: int = 24) -> List[SecurityEvent]:
        """
        Get critical events from the last N hours.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of critical events
        """
        since = time.time() - (hours * 3600)
        return self.get_events(
            severity=SecuritySeverity.CRITICAL,
            since=since,
            limit=1000
        )
    
    def correlate_events(
        self,
        event_type: SecurityEventType,
        time_window: int = 300,
        threshold: int = 5
    ) -> List[List[SecurityEvent]]:
        """
        Correlate events of the same type within a time window.
        
        Args:
            event_type: Type of events to correlate
            time_window: Time window in seconds (default: 5 minutes)
            threshold: Minimum number of events to trigger correlation
            
        Returns:
            List of correlated event groups
        """
        with self._lock:
            events = [e for e in self.events if e.event_type == event_type]
            events.sort(key=lambda e: e.timestamp)
            
            correlated = []
            current_group = []
            
            for event in events:
                if not current_group:
                    current_group.append(event)
                else:
                                                                                 
                    if event.timestamp - current_group[-1].timestamp <= time_window:
                        current_group.append(event)
                    else:
                                                        
                        if len(current_group) >= threshold:
                            correlated.append(current_group)
                        current_group = [event]
            
            if len(current_group) >= threshold:
                correlated.append(current_group)
            
            return correlated
    
    def detect_malicious_plugin_behavior(self, plugin_name: str) -> bool:
        """
        Detect if a plugin is exhibiting malicious behavior.
        
        Args:
            plugin_name: Name of plugin to check
            
        Returns:
            True if malicious behavior detected, False otherwise
        """
        with self._lock:
                                        
            errors = [e for e in self.events 
                     if e.source == plugin_name and e.event_type == SecurityEventType.PLUGIN_ERROR]
            
            if len(errors) > 10:                                     
                logger.warning(f"Malicious behavior detected in plugin {plugin_name}: excessive errors")
                return True
            
            integrity_failures = [e for e in self.events 
                                if e.source == plugin_name and e.event_type == SecurityEventType.INTEGRITY_FAILURE]
            
            if len(integrity_failures) > 0:
                logger.warning(f"Malicious behavior detected in plugin {plugin_name}: integrity failures")
                return True
        
        return False

_security_logger: Optional[SecurityEventLogger] = None
_logger_lock = Lock()

def get_security_logger() -> SecurityEventLogger:
    """
    Get the global security event logger instance.
    
    Returns:
        SecurityEventLogger instance
    """
    global _security_logger
    
    with _logger_lock:
        if _security_logger is None:
            _security_logger = SecurityEventLogger()
    
    return _security_logger
