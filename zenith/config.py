"""YAML configuration loader for Zenith-Sentry."""

import os
import yaml
import logging

logger = logging.getLogger(__name__)


class ConfigLoader:
    """Loads and parses YAML configuration files."""
    
    def __init__(self, path: str):
        """Initialize config loader.
        
        Args:
            path: Path to YAML configuration file
        """
        self.config = {}
        self.path = path
        
        if not os.path.exists(path):
            logger.warning(f"Config file not found: {path}")
            return
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
                if content and isinstance(content, dict):
                    self.config = content
                    logger.info(f"Config loaded from {path}")
                else:
                    logger.warning(f"Config file is empty or invalid: {path}")
        except yaml.YAMLError as e:
            logger.error(f"YAML parse error in {path}: {e}")
        except IOError as e:
            logger.error(f"Failed to read config: {e}")
        except Exception as e:
            logger.error(f"Unexpected error loading config: {e}")
    
    def get(self, key: str, default=None):
        """Get configuration value by key.
        
        Args:
            key: Configuration key (dot-separated paths not supported)
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        return self.config.get(key, default)
    
    def __repr__(self):
        """Return config representation."""
        return f"ConfigLoader({self.path})"

