import psutil
class ProcessCollector:
    def collect(self):
        procs = {}
        for p in psutil.process_iter(['pid', 'name', 'cmdline']):
            try: procs[p.pid] = p.info
            except: continue
        return procs
class NetworkCollector:
    def collect(self): return []
class SystemCollector:
    def __init__(self, scan_dirs): self.scan_dirs = scan_dirs
    def collect(self): return {}
