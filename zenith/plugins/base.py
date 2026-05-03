#!/usr/bin/env python3
"""
Plugin base class and plugin system for Zenith-Sentry.
Provides a plugin architecture for extensibility.
"""
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class PluginInfo:
    """Plugin metadata."""
    name: str
    version: str
    author: str
    description: str
    dependencies: List[str] = None

class Plugin(ABC):
    """Base class for Zenith-Sentry plugins."""
    
    def __init__(self):
        """Initialize the plugin."""
        self.enabled = True
        self.config: Dict[str, Any] = {}
    
    @abstractmethod
    def get_info(self) -> PluginInfo:
        """
        Get plugin information.
        
        Returns:
            PluginInfo object with plugin metadata
        """
        pass
    
    def initialize(self, config: Dict[str, Any]) -> None:
        """
        Initialize the plugin with configuration.
        
        Args:
            config: Plugin configuration dictionary
        """
        self.config = config
        logger.info(f"Initializing plugin: {self.get_info().name}")
    
    def on_load(self) -> None:
        """Called when the plugin is loaded."""
        logger.info(f"Plugin loaded: {self.get_info().name}")
    
    def on_unload(self) -> None:
        """Called when the plugin is unloaded."""
        logger.info(f"Plugin unloaded: {self.get_info().name}")
    
    def enable(self) -> None:
        """Enable the plugin."""
        self.enabled = True
        logger.info(f"Plugin enabled: {self.get_info().name}")
    
    def disable(self) -> None:
        """Disable the plugin."""
        self.enabled = False
        logger.info(f"Plugin disabled: {self.get_info().name}")

class DetectorPlugin(Plugin):
    """Base class for detector plugins."""
    
    @abstractmethod
    def detect(self, procs: Dict, conns: List, sys_files: Dict, ebpf_events: List, config: Dict) -> List:
        """
        Run detection logic.
        
        Args:
            procs: Process information dictionary
            conns: Network connections list
            sys_files: System files dictionary
            ebpf_events: eBPF events list
            config: Configuration dictionary
            
        Returns:
            List of findings
        """
        pass

class CollectorPlugin(Plugin):
    """Base class for collector plugins."""
    
    @abstractmethod
    def collect(self, config: Dict) -> Any:
        """
        Collect telemetry data.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Collected data
        """
        pass

class MitigationPlugin(Plugin):
    """Base class for mitigation plugins."""
    
    @abstractmethod
    def mitigate(self, target: str, reason: str) -> bool:
        """
        Perform mitigation action.
        
        Args:
            target: Target of mitigation (PID, IP, etc.)
            reason: Reason for mitigation
            
        Returns:
            True if mitigation succeeded, False otherwise
        """
        pass

class PluginManager:
    """Manages plugin lifecycle and registration."""
    
    def __init__(self):
        """Initialize the plugin manager."""
        self.plugins: Dict[str, Plugin] = {}
        self.plugin_order: List[str] = []
    
    def register_plugin(self, plugin: Plugin) -> None:
        """
        Register a plugin.
        
        Args:
            plugin: Plugin instance to register
        """
        info = plugin.get_info()
        plugin_name = info.name
        
        if plugin_name in self.plugins:
            logger.warning(f"Plugin {plugin_name} already registered, overwriting")
        
        self.plugins[plugin_name] = plugin
        self.plugin_order.append(plugin_name)
        logger.info(f"Registered plugin: {plugin_name} v{info.version}")
    
    def unregister_plugin(self, plugin_name: str) -> None:
        """
        Unregister a plugin.
        
        Args:
            plugin_name: Name of plugin to unregister
        """
        if plugin_name in self.plugins:
            plugin = self.plugins[plugin_name]
            plugin.on_unload()
            del self.plugins[plugin_name]
            self.plugin_order.remove(plugin_name)
            logger.info(f"Unregistered plugin: {plugin_name}")
    
    def get_plugin(self, plugin_name: str) -> Optional[Plugin]:
        """
        Get a plugin by name.
        
        Args:
            plugin_name: Name of plugin
            
        Returns:
            Plugin instance or None if not found
        """
        return self.plugins.get(plugin_name)
    
    def get_plugins_by_type(self, plugin_type: type) -> List[Plugin]:
        """
        Get all plugins of a specific type.
        
        Args:
            plugin_type: Plugin class type (e.g., DetectorPlugin)
            
        Returns:
            List of plugins of the specified type
        """
        return [p for p in self.plugins.values() if isinstance(p, plugin_type)]
    
    def initialize_all(self, config: Dict[str, Any]) -> None:
        """
        Initialize all plugins.
        
        Args:
            config: Global configuration dictionary
        """
        for plugin_name in self.plugin_order:
            plugin = self.plugins[plugin_name]
            plugin_config = config.get("plugins", {}).get(plugin_name, {})
            plugin.initialize(plugin_config)
            plugin.on_load()
    
    def shutdown_all(self) -> None:
        """Shutdown all plugins."""
        for plugin_name in self.plugin_order:
            plugin = self.plugins[plugin_name]
            plugin.on_unload()

_plugin_manager: Optional[PluginManager] = None

def get_plugin_manager() -> PluginManager:
    """
    Get the global plugin manager instance.
    
    Returns:
        PluginManager instance
    """
    global _plugin_manager
    if _plugin_manager is None:
        _plugin_manager = PluginManager()
    return _plugin_manager
