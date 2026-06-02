import os
import datetime
import psutil
import logging
from zenith.utils.validation import validate_filepath

logger = logging.getLogger(__name__)

MAX_SYSTEM_FILES = 10000

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
    ALLOWED_SCAN_DIRS = {
        "/etc/systemd/system",
        "/etc/cron.d",
        "/etc/rc.local",
        "/etc/init.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
        "/etc/profile.d",
        "/etc/update-motd.d",
    }

    def __init__(self, scan_dirs):
        validated = []
        for d in (scan_dirs or []):
            is_valid, _ = validate_filepath(d)
            if is_valid:
                validated.append(d)
            else:
                logger.warning(f"Rejected invalid scan_dir: {d}")
        self.scan_dirs = validated

    def collect(self):
        findings = {}
        search_paths = list(set(self.scan_dirs + list(self.ALLOWED_SCAN_DIRS)))
        file_count = 0
        for path in search_paths:
            if not os.path.exists(path):
                continue
            is_valid, error = validate_filepath(path)
            if not is_valid:
                logger.warning(f"Skipping invalid scan path {path}: {error}")
                continue
            try:
                if os.path.isfile(path):
                    if file_count >= MAX_SYSTEM_FILES:
                        logger.warning("Max system file scan limit reached")
                        break
                    findings[path] = self._get_file_info(path)
                    file_count += 1
                elif os.path.isdir(path):
                    for root, _, files in os.walk(path, followlinks=False):
                        for f in files:
                            if file_count >= MAX_SYSTEM_FILES:
                                logger.warning("Max system file scan limit reached")
                                break
                            full_path = os.path.join(root, f)
                            if os.path.islink(full_path):
                                continue
                            findings[full_path] = self._get_file_info(full_path)
                            file_count += 1
                        if file_count >= MAX_SYSTEM_FILES:
                            break
            except Exception as e:
                logger.warning(f"Error scanning persistence path {path}: {e}")
        return findings

    def _get_file_info(self, path):
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
