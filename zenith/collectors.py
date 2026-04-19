import psutil
import logging
logger = logging.getLogger(__name__)
class ProcessCollector:
    def collect(self):
        procs = {}
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    procs[proc.pid] = proc.info
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    logger.warning(f"Error reading process {proc.pid}: {type(e).__name__}")
                    continue
        except Exception as e:
            logger.error(f"Process enumeration failed: {e}")
        return procs
class NetworkCollector:
    def collect(self):
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    connections.append({
                        "fd": conn.fd,
                        "family": str(conn.family),
                        "type": str(conn.type),
                        "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        "status": conn.status,
                        "pid": conn.pid
                    })
                except Exception:
                    continue
        except Exception as e:
            logger.error(f"Network enumeration failed: {e}")
        return connections
class SystemCollector:
    def __init__(self, scan_dirs):
        self.scan_dirs = scan_dirs or []
    def collect(self):
        import os
        findings = {}
        standard_dirs = [
            "/etc/systemd/system",
            "/etc/cron.d",
            "/etc/rc.local",
            "/etc/init.d"
        ]
        search_paths = list(set(self.scan_dirs + standard_dirs))
        for path in search_paths:
            if not os.path.exists(path):
                continue
            try:
                if os.path.isfile(path):
                    findings[path] = self._get_file_info(path)
                elif os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for f in files:
                            full_path = os.path.join(root, f)
                            findings[full_path] = self._get_file_info(full_path)
            except Exception as e:
                logger.warning(f"Error scanning persistence path {path}: {e}")
        return findings
    def _get_file_info(self, path):
        import os
        import datetime
        try:
            stat = os.stat(path)
            return {
                "size": stat.st_size,
                "mtime": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "mode": oct(stat.st_mode),
                "uid": stat.st_uid,
                "gid": stat.st_gid
            }
        except Exception:
            return {"error": "Access Denied"}
