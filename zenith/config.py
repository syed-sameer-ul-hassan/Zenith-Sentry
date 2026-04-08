import yaml, os
class ConfigLoader:
    def __init__(self, path: str):
        self.config = {}
        if os.path.exists(path):
            with open(path, 'r') as f: self.config = yaml.safe_load(f) or {}
    def get(self, key, default=None): return self.config.get(key, default)
