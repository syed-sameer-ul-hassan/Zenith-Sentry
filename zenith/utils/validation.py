#!/usr/bin/env python3
"""
Input validation utilities for security hardening.
Provides path sanitization, file size limits, and permission checks.
"""
import os
import re
import logging
from pathlib import Path
from typing import Optional, Tuple
from typing import Union

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 10 * 1024 * 1024        
ALLOWED_PATHS = [
    '/etc',
    '/var',
    '/home',
    '/opt',
    '/usr/local',
    '/tmp',
    '/dev/shm',
]
DENIED_PATTERNS = [
    r'\.\./',                       
    r'~$',                   
    r'\.bak$',               
    r'\.swp$',                 
]

def validate_filepath(filepath: Union[str, Path]) -> Tuple[bool, Optional[str]]:
    """
    Validate a file path for security.
    
    Args:
        filepath: Path to validate (string or Path object)
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        if not filepath:
            return False, "File path is empty"
        
        filepath_str = str(filepath)
        
        if not filepath_str or not filepath_str.strip():
            return False, "File path is empty or whitespace"
        
        for pattern in DENIED_PATTERNS:
            if re.search(pattern, filepath_str):
                return False, f"Path contains denied pattern: {pattern}"
        
        try:
            abs_path = os.path.abspath(os.path.expanduser(filepath_str))
        except (OSError, ValueError) as e:
            return False, f"Invalid path: {str(e)}"
        
        is_allowed = False
        for allowed in ALLOWED_PATHS:
            if abs_path.startswith(allowed):
                is_allowed = True
                break
        
        if not is_allowed:
            logger.warning(f"Path outside allowed directories: {abs_path}")
                                                                      
        suspicious_chars = ['\x00', '\r', '\n']
        for char in suspicious_chars:
            if char in filepath_str:
                return False, f"Path contains suspicious character: {repr(char)}"
        
        return True, None
        
    except Exception as e:
        logger.error(f"Error validating filepath {filepath}: {e}")
        return False, f"Validation error: {str(e)}"

def check_file_size(filepath: Union[str, Path], max_size: int = MAX_FILE_SIZE) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Check if file size is within limits.
    
    Args:
        filepath: Path to check
        max_size: Maximum allowed size in bytes (default: 10MB)
        
    Returns:
        Tuple of (is_valid, actual_size, error_message)
    """
    try:
        filepath_str = str(filepath)
        
        if not os.path.exists(filepath_str):
            return False, None, f"File does not exist: {filepath_str}"
        
        if not os.path.isfile(filepath_str):
            return False, None, f"Path is not a file: {filepath_str}"
        
        file_size = os.path.getsize(filepath_str)
        
        if file_size > max_size:
            return False, file_size, f"File too large: {file_size} bytes (max: {max_size})"
        
        return True, file_size, None
        
    except OSError as e:
        logger.error(f"Error checking file size for {filepath}: {e}")
        return False, None, f"File size check error: {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error checking file size for {filepath}: {e}")
        return False, None, f"Unexpected error: {str(e)}"

def check_permissions(filepath: Union[str, Path], 
                    required_read: bool = True,
                    required_write: bool = False,
                    required_execute: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Check if file has required permissions.
    
    Args:
        filepath: Path to check
        required_read: Require read permission
        required_write: Require write permission
        required_execute: Require execute permission
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        filepath_str = str(filepath)
        
        if not os.path.exists(filepath_str):
            return False, f"File does not exist: {filepath_str}"
        
        if required_read and not os.access(filepath_str, os.R_OK):
            return False, f"Read permission denied: {filepath_str}"
        
        if required_write and not os.access(filepath_str, os.W_OK):
            return False, f"Write permission denied: {filepath_str}"
        
        if required_execute and not os.access(filepath_str, os.X_OK):
            return False, f"Execute permission denied: {filepath_str}"
        
        return True, None
        
    except OSError as e:
        logger.error(f"Error checking permissions for {filepath}: {e}")
        return False, f"Permission check error: {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error checking permissions for {filepath}: {e}")
        return False, f"Unexpected error: {str(e)}"

def validate_ebpf_source(filepath: Union[str, Path]) -> Tuple[bool, Optional[str]]:
    """
    Comprehensive validation for eBPF source files.
    
    Args:
        filepath: Path to eBPF C source file
        
    Returns:
        Tuple of (is_valid, error_message)
    """
                   
    is_valid, error = validate_filepath(filepath)
    if not is_valid:
        return False, f"Path validation failed: {error}"
    
    filepath_str = str(filepath)
    if not filepath_str.endswith('.c'):
        return False, "eBPF source must be a .c file"
    
    is_valid, size, error = check_file_size(filepath, MAX_FILE_SIZE)
    if not is_valid:
        return False, f"File size check failed: {error}"
    
    is_valid, error = check_permissions(filepath, required_read=True)
    if not is_valid:
        return False, f"Permission check failed: {error}"
    
    try:
        with open(filepath_str, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(1000)                  
            if 'BPF' not in content and 'bpf' not in content:
                logger.warning(f"File may not be a valid eBPF source: {filepath_str}")
                                        
    except Exception as e:
        logger.error(f"Error reading eBPF source {filepath}: {e}")
        return False, f"Error reading file: {str(e)}"
    
    return True, None

def sanitize_path(path: str) -> str:
    """
    Sanitize a path string by removing potentially dangerous elements.
    
    Args:
        path: Path to sanitize
        
    Returns:
        Sanitized path string
    """
    try:
                           
        path = path.replace('\x00', '')
        
        path = path.replace('\r', '').replace('\n', '')
        
        path = path.strip()
        
        path = os.path.expanduser(path)
        
        path = os.path.abspath(path)
        
        path = os.path.normpath(path)
        
        return path
        
    except Exception as e:
        logger.error(f"Error sanitizing path {path}: {e}")
        return path                                         

def validate_ip_address(ip: str) -> Tuple[bool, Optional[str]]:
    """
    Validate an IP address string.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        if not ip or not ip.strip():
            return False, "IP address is empty"
        
        ip = ip.strip()
        
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$'
        
        if re.match(ipv4_pattern, ip):
                                 
            octets = ip.split('.')
            for octet in octets:
                val = int(octet)
                if val < 0 or val > 255:
                    return False, f"Invalid octet in IPv4: {octet}"
            return True, None
        
        if re.match(ipv6_pattern, ip):
            return True, None
        
        return False, "Invalid IP address format"
        
    except Exception as e:
        logger.error(f"Error validating IP address {ip}: {e}")
        return False, f"IP validation error: {str(e)}"
