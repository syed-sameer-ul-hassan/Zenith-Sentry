#!/usr/bin/env python3
"""
Logging utilities with security features.
Provides log sanitization to remove sensitive information from logs.
"""
import logging
import re
from typing import Optional, Set

logger = logging.getLogger(__name__)

SENSITIVE_PATTERNS = [
                  
    r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                   
    r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b',
                     
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
           
    r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
                                
    r'\b[A-Za-z0-9]{32,}\b',
                                 
    r'\b(bearer|token|key|secret|password|passwd)\s*[:=]\s*[A-Za-z0-9_\-\.]+\b',
                                         
    r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
]

SENSITIVE_KEYWORDS = {
    'password', 'passwd', 'secret', 'token', 'key', 'apikey', 'api_key',
    'credential', 'auth', 'authorization', 'bearer', 'session', 'cookie',
    'private', 'ssn', 'social_security', 'credit_card', 'card_number'
}

def sanitize_log_entry(log_message: str) -> str:
    """
    Sanitize a log message by removing sensitive information.
    
    Args:
        log_message: Original log message
        
    Returns:
        Sanitized log message with sensitive data redacted
    """
    if not log_message:
        return log_message
    
    sanitized = log_message
    
    for pattern in SENSITIVE_PATTERNS:
        sanitized = re.sub(pattern, '[REDACTED]', sanitized, flags=re.IGNORECASE)
    
    for keyword in SENSITIVE_KEYWORDS:
                                                                     
        pattern = rf'\b{keyword}\s*[:=]\s*\S+'
        sanitized = re.sub(pattern, f'{keyword}=[REDACTED]', sanitized, flags=re.IGNORECASE)
    
    return sanitized

def sanitize_dict(data: dict, exclude_keys: Optional[Set[str]] = None) -> dict:
    """
    Sanitize a dictionary by redacting sensitive values.
    
    Args:
        data: Dictionary to sanitize
        exclude_keys: Set of keys to exclude from sanitization
        
    Returns:
        Sanitized dictionary
    """
    if exclude_keys is None:
        exclude_keys = set()
    
    sanitized = {}
    for key, value in data.items():
                                                 
        key_lower = key.lower()
        is_sensitive = any(keyword in key_lower for keyword in SENSITIVE_KEYWORDS)
        
        if is_sensitive and key not in exclude_keys:
                              
            if isinstance(value, str):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                sanitized[key] = sanitize_dict(value, exclude_keys)
            else:
                sanitized[key] = '[REDACTED]'
        else:
                                                        
            if isinstance(value, str):
                sanitized[key] = sanitize_log_entry(value)
            elif isinstance(value, dict):
                sanitized[key] = sanitize_dict(value, exclude_keys)
            else:
                sanitized[key] = value
    
    return sanitized

class SecureLogFormatter(logging.Formatter):
    """
    Custom log formatter that sanitizes log messages.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record with sanitization.
        
        Args:
            record: Log record to format
            
        Returns:
            Formatted and sanitized log message
        """
                              
        record.msg = sanitize_log_entry(str(record.msg))
        
        if hasattr(record, 'args') and record.args:
            sanitized_args = tuple(
                sanitize_log_entry(str(arg)) if isinstance(arg, str) else arg
                for arg in record.args
            )
            record.args = sanitized_args
        
        return super().format(record)

def setup_secure_logging(
    log_file: str,
    log_level: int = logging.INFO,
    enable_sanitization: bool = True
) -> logging.Logger:
    """
    Setup secure logging with sanitization.
    
    Args:
        log_file: Path to log file
        log_level: Logging level (default: INFO)
        enable_sanitization: Whether to enable log sanitization (default: True)
        
    Returns:
        Configured logger instance
    """
                   
    secure_logger = logging.getLogger('zenith')
    secure_logger.setLevel(log_level)
    
    secure_logger.handlers.clear()
    
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)
    
    if enable_sanitization:
        formatter = SecureLogFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    file_handler.setFormatter(formatter)
    secure_logger.addHandler(file_handler)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    secure_logger.addHandler(console_handler)
    
    return secure_logger
