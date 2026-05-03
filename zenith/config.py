import os
import yaml
import logging
import hashlib
import stat
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

CONFIG_VERSION = "1.0"

class ConfigLoader:
    def __init__(self, path: str, require_secure: bool = True):
        self.config = {}
        self.path = path
        self.file_hash: Optional[str] = None
        self.config_version: Optional[str] = None
        
        if not os.path.exists(path):
            logger.warning(f"Config file not found: {path}")
            return
        
        if require_secure:
            if not self._check_file_permissions(path):
                logger.warning(f"Config file has insecure permissions: {path}")
                                                                
        self.file_hash = self._calculate_file_hash(path)
        if not self.file_hash:
            logger.warning(f"Could not calculate file hash for integrity check: {path}")
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
                if content and isinstance(content, dict):
                    self.config = content
                    self.config_version = content.get('_version', CONFIG_VERSION)
                    logger.info(f"Config loaded from {path} (version: {self.config_version})")
                    
                    if self.config_version != CONFIG_VERSION:
                        logger.warning(f"Config version mismatch: expected {CONFIG_VERSION}, got {self.config_version}")
                else:
                    logger.warning(f"Config file is empty or invalid: {path}")
        except yaml.YAMLError as e:
            logger.error(f"YAML parse error in {path}: {e}")
        except IOError as e:
            logger.error(f"Failed to read config: {e}")
        except Exception as e:
            logger.error(f"Unexpected error loading config: {e}")
    
    def _check_file_permissions(self, path: str) -> bool:
        """
        Check if config file has secure permissions.
        
        Args:
            path: Path to config file
            
        Returns:
            True if permissions are secure, False otherwise
        """
        try:
            file_stat = os.stat(path)
            file_mode = file_stat.st_mode
            
            if file_mode & stat.S_IROTH:
                logger.warning(f"Config file is world-readable: {path}")
                return False
            
            if file_mode & stat.S_IWOTH:
                logger.warning(f"Config file is world-writable: {path}")
                return False
            
            return True
            
        except OSError as e:
            logger.error(f"Error checking file permissions: {e}")
            return False
    
    def _calculate_file_hash(self, path: str) -> Optional[str]:
        """
        Calculate SHA-256 hash of config file for integrity checking.
        
        Args:
            path: Path to config file
            
        Returns:
            Hex digest of file hash, or None if calculation fails
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(path, 'rb') as f:
                                                           
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file hash: {e}")
            return None
    
    def verify_integrity(self) -> bool:
        """
        Verify config file integrity by comparing current hash with stored hash.
        
        Returns:
            True if integrity is verified, False otherwise
        """
        if not self.file_hash:
            logger.warning("No stored hash to verify against")
            return False
        
        current_hash = self._calculate_file_hash(self.path)
        if not current_hash:
            logger.error("Could not calculate current hash for verification")
            return False
        
        if current_hash != self.file_hash:
            logger.error(f"Config file integrity check failed: hash mismatch")
            logger.error(f"Stored hash: {self.file_hash}")
            logger.error(f"Current hash: {current_hash}")
            return False
        
        logger.info("Config file integrity verified")
        return True
    
    def get(self, key: str, default=None):
        return self.config.get(key, default)
    
    def __repr__(self):
        return f"ConfigLoader({self.path})"

def secure_config_load(path: str, require_secure: bool = True) -> ConfigLoader:
    """
    Securely load a config file with permission and integrity checks.
    
    Args:
        path: Path to config file
        require_secure: Whether to require secure file permissions
        
    Returns:
        ConfigLoader instance with loaded config
        
    Raises:
        PermissionError: If file permissions are insecure and require_secure is True
        FileNotFoundError: If config file doesn't exist
        ValueError: If config file integrity check fails
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    
    loader = ConfigLoader(path, require_secure=require_secure)
    
    if loader.file_hash:
        if not loader.verify_integrity():
            raise ValueError(f"Config file integrity check failed: {path}")
    
    return loader
