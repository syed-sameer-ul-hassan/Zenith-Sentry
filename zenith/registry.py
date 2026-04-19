import os
import sys
import importlib.util
import inspect
import logging
from pathlib import Path
from zenith.core import IDetector
logger = logging.getLogger(__name__)
class PluginRegistry:
    def __init__(self):
        self.plugin_dir = os.path.join(os.path.dirname(__file__), 'plugins')
        self.classes = []
        self.errors = []
    def load_plugins(self):
        if not os.path.exists(self.plugin_dir):
            logger.warning(f"Plugin directory not found: {self.plugin_dir}")
            return
        logger.debug(f"Loading plugins from {self.plugin_dir}")
        for filename in os.listdir(self.plugin_dir):
            if not filename.endswith(".py") or filename.startswith("__"):
                continue
            try:
                self._load_plugin_file(filename)
            except Exception as e:
                error_msg = f"Failed to load {filename}: {type(e).__name__}: {e}"
                logger.error(error_msg)
                self.errors.append(error_msg)
    def _load_plugin_file(self, filename: str):
        mod_name = f"zenith.plugins.{filename[:-3]}"
        path = os.path.join(self.plugin_dir, filename)
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if not spec or not spec.loader:
            logger.warning(f"Could not create module spec for {filename}")
            return
        try:
            mod = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = mod
            spec.loader.exec_module(mod)
        except SyntaxError as e:
            raise SyntaxError(f"Syntax error in {filename}: {e}") from e
        except Exception as e:
            raise RuntimeError(f"Failed to execute module {filename}: {e}") from e
        detector_count = 0
        for name, obj in inspect.getmembers(mod):
            try:
                if not inspect.isclass(obj):
                    continue
                if not issubclass(obj, IDetector) or obj is IDetector:
                    continue
                self.classes.append(obj)
                detector_count += 1
                logger.debug(f"Loaded detector: {obj.__name__}")
            except Exception as e:
                logger.warning(f"Error inspecting {name}: {e}")
        if detector_count > 0:
            logger.info(f"Loaded {detector_count} detector(s) from {filename}")
    def instantiate(self, **kwargs) -> list:
        detectors = []
        for cls in self.classes:
            try:
                detector = cls(**kwargs)
                detectors.append(detector)
                logger.debug(f"Instantiated: {cls.__name__}")
            except Exception as e:
                logger.error(f"Failed to instantiate {cls.__name__}: {e}")
        return detectors
