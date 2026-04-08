import os, importlib.util, inspect, sys
from zenith.core import IDetector

class PluginRegistry:
    def __init__(self):
        self.plugin_dir = os.path.join(os.path.dirname(__file__), 'plugins')
        self.classes = []

    def load_plugins(self):
        if not os.path.exists(self.plugin_dir): return
        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                mod_name = f"zenith.plugins.{filename[:-3]}"
                path = os.path.join(self.plugin_dir, filename)
                spec = importlib.util.spec_from_file_location(mod_name, path)
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    sys.modules[mod_name] = mod
                    spec.loader.exec_module(mod)
                    for name, obj in inspect.getmembers(mod):
                        if inspect.isclass(obj) and issubclass(obj, IDetector) and obj is not IDetector:
                            self.classes.append(obj)

    def instantiate(self, **kwargs): return [cls(**kwargs) for cls in self.classes]
