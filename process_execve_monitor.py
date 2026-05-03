#!/usr/bin/env python3
import ctypes
import signal
import subprocess
import socket
import struct
import sys
import json
import time
import os
import shlex
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from zenith.utils.validation import validate_ebpf_source, validate_ip_address
from zenith.utils.signals import register_signal_handler, SignalMask
try:
    BPF = __import__('bcc').BPF
    HAS_BCC = True
except (ImportError, AttributeError):
    HAS_BCC = False
    BPF = None
    print("[WARN] BCC library not found. eBPF components will be disabled.")
CRITICAL_PORTS: Set[int] = {1337, 4444, 5555}
CRITICAL_BINS:  Set[str] = {"nc", "ncat", "nmap", "socat", "bash", "sh"}
SUSPICIOUS_PATHS: List[str] = ["/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"]
SAFE_MODE: bool = True
class ExecveEvent(ctypes.Structure):
    _fields_ = [
        ("pid",          ctypes.c_uint32),
        ("tgid",         ctypes.c_uint32),
        ("ppid",         ctypes.c_uint32),
        ("uid",          ctypes.c_uint32),
        ("gid",          ctypes.c_uint32),
        ("comm",         ctypes.c_char * 16),
        ("filename",     ctypes.c_char * 256),
        ("timestamp_ns", ctypes.c_uint64),
        ("event_type",   ctypes.c_uint8),
    ]
class ConnectEvent(ctypes.Structure):
    _fields_ = [
        ("pid",        ctypes.c_uint32),
        ("tgid",       ctypes.c_uint32),
        ("uid",        ctypes.c_uint32),
        ("daddr",      ctypes.c_uint32),
        ("dport",      ctypes.c_uint16),
        ("event_type", ctypes.c_uint8),
    ]
_blocked_ips: Set[str] = set()
                                            
IP_WHITELIST = {
    '127.0.0.1',             
    '0.0.0.0',                     
    '::1',                         
}
def mitigate(pid: int, ip: Optional[str] = None, reason: str = "") -> None:
    tag = "[SAFE MODE]" if SAFE_MODE else "[MITIGATION]"
    print(f"\n{tag} THREAT DETECTED — {reason}")
    print(f"{tag}   PID  : {pid}")
    if ip:
        print(f"{tag}   IP   : {ip}")
    if SAFE_MODE:
        if ip:
            print(f"{tag}   Action: Would execute → iptables -A OUTPUT -d {ip} -j DROP")
        print(f"{tag}   Action: Would execute → kill -9 {pid}\n")
        return
    print(f"[MITIGATION] Sending SIGKILL to PID {pid}...")
    try:
        os.kill(pid, signal.SIGKILL)
        print(f"[MITIGATION] PID {pid} killed.")
    except ProcessLookupError:
        print(f"[MITIGATION] PID {pid} already exited.")
    except OSError as e:
        print(f"[MITIGATION] Kill failed: {e}")
    if ip and ip not in _blocked_ips:
                                             
        is_valid, error = validate_ip_address(ip)
        if not is_valid:
            print(f"[MITIGATION] IP validation failed: {error}")
            print(f"[MITIGATION] Skipping iptables block for invalid IP")
            return
        
        if ip in IP_WHITELIST:
            print(f"[MITIGATION] IP {ip} is whitelisted - skipping block")
            return
        
        print(f"[MITIGATION] Blocking {ip} via iptables...")
                                                        
        try:
            result = subprocess.run(
                ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True, text=True,
                check=False                                          
            )
            if result.returncode == 0:
                _blocked_ips.add(ip)
                print(f"[MITIGATION] {ip} blocked successfully.")
            else:
                print(f"[MITIGATION] iptables failed: {result.stderr.strip()}")
        except subprocess.SubprocessError as e:
            print(f"[MITIGATION] iptables command error: {e}")
    print()
class ProcessExecutionMonitor:
    EVENT_EXECVE_ENTER  = 1
    EVENT_EXECVE_FAILED = 2
    EVENT_TCP_CONNECT   = 3
    def __init__(self, ebpf_source: str, enable_json: bool = True,
                 safe_mode: bool = True, config: Optional[Dict] = None):
        self.ebpf_source  = ebpf_source
        self.json_output  = enable_json
        self.config       = config or {}
        ebpf_cfg = self.config.get("ebpf", {})
        global CRITICAL_PORTS, CRITICAL_BINS, SUSPICIOUS_PATHS, SAFE_MODE
        CRITICAL_PORTS = set(ebpf_cfg.get("critical_ports", list(CRITICAL_PORTS)))
        CRITICAL_BINS  = set(ebpf_cfg.get("critical_bins",  list(CRITICAL_BINS)))
        SUSPICIOUS_PATHS = ebpf_cfg.get("suspicious_paths", SUSPICIOUS_PATHS)
        SAFE_MODE = safe_mode and ebpf_cfg.get("mitigation", {}).get("safe_mode", True)
        self.event_count  = 0
        self.alert_count  = 0
        self.start_time   = time.time()
        self.bpf          = None
        self._running     = False
        self.captured_events: List[Dict] = []
        self.captured_alerts: List[Dict] = []
                                         
        register_signal_handler(signal.SIGINT, self._handle_signal)
        register_signal_handler(signal.SIGTERM, self._handle_signal)
        self._load_ebpf()
    def _load_ebpf(self) -> None:
                                                  
        is_valid, error = validate_ebpf_source(self.ebpf_source)
        if not is_valid:
            print(f"[ERROR] eBPF source validation failed: {error}")
            sys.exit(1)
        
        try:
            with open(self.ebpf_source, 'r') as f:
                program_text = f.read()
        except FileNotFoundError:
            print(f"[ERROR] eBPF source not found: {self.ebpf_source}")
            sys.exit(1)
        try:
            self.bpf = BPF(text=program_text)
            print("[+] eBPF program compiled and loaded")
        except Exception as e:
            print(f"[ERROR] Failed to compile eBPF: {e}")
            sys.exit(1)
        print("[+] Tracepoints attached: sys_enter_execve, sys_exit_execve")
        print("[+] kprobe attached:      tcp_v4_connect")
        self.bpf["event_table"].open_perf_buffer(self._handle_execve_event)
        try:
            self.bpf["connect_events"].open_perf_buffer(self._handle_connect_event)
            print("[+] Perf buffers opened for execve + tcp_connect")
        except KeyError:
            print("[WARN] connect_events perf buffer not found — TCP monitoring skipped")
    def _handle_execve_event(self, cpu, data, size) -> None:
        event = ctypes.cast(data, ctypes.POINTER(ExecveEvent)).contents
        self.event_count += 1
        try:
            comm     = event.comm.decode('utf-8', 'replace').rstrip('\x00')
            filename = event.filename.decode('utf-8', 'replace').rstrip('\x00')
        except Exception as e:
            print(f"[WARN] Failed to decode execve event: {e}")
            return
        if self.json_output:
            self._output_execve_json(event, comm, filename)
        else:
            self._output_execve_human(event, comm, filename)
        self.captured_events.append({
            "type": {1: "EXECVE_ENTER", 2: "EXECVE_FAILED"}.get(event.event_type, "UNKNOWN"),
            "timestamp": datetime.fromtimestamp(event.timestamp_ns / 1e9).isoformat(),
            "process": {
                "pid":  event.pid,
                "tgid": event.tgid,
                "uid":  event.uid,
                "gid":  event.gid,
                "name": comm,
            },
            "binary": filename,
            "seq":    self.event_count,
        })
        self._check_execve_watchlist(event, comm, filename)
        self._check_threat_heuristics(event, comm, filename)
    def _handle_connect_event(self, cpu, data, size) -> None:
        event = ctypes.cast(data, ctypes.POINTER(ConnectEvent)).contents
        self.event_count += 1
        try:
            ip = socket.inet_ntoa(struct.pack("I", event.daddr))
        except Exception:
            ip = "0.0.0.0"
        if self.json_output:
            self._output_connect_json(event, ip)
        else:
            self._output_connect_human(event, ip)
        self.captured_events.append({
            "type":      "TCP_CONNECT",
            "timestamp": datetime.now().isoformat(),
            "process": {
                "pid":  event.pid,
                "tgid": event.tgid,
                "uid":  event.uid,
            },
            "destination": {"ip": ip, "port": event.dport},
            "seq":    self.event_count,
        })
        self._check_connect_watchlist(event, ip)
    def _check_execve_watchlist(self, event: ExecveEvent,
                                comm: str, filename: str) -> None:
        basename = os.path.basename(filename)
        if basename in CRITICAL_BINS:
            self.alert_count += 1
            reason = f"Critical binary executed: {filename}"
            print(f"[!] WATCHLIST HIT — {reason} (PID {event.pid}, UID {event.uid})")
            mitigate(event.pid, reason=reason)
    def _check_connect_watchlist(self, event: ConnectEvent, ip: str) -> None:
        if event.dport in CRITICAL_PORTS:
            self.alert_count += 1
            reason = f"Connection to critical port {event.dport} at {ip}"
            print(f"[!] WATCHLIST HIT — {reason} (PID {event.pid})")
            mitigate(event.pid, ip=ip, reason=reason)
    def _check_threat_heuristics(self, event: ExecveEvent,
                                  comm: str, filename: str) -> None:
        alerts = []
        if any(filename.startswith(p) for p in SUSPICIOUS_PATHS):
            alerts.append(f"Binary in suspicious location: {filename}")
        if event.event_type == self.EVENT_EXECVE_FAILED:
            alerts.append(f"execve failure (possible evasion): {filename}")
        if alerts:
            self.alert_count += 1
            alert_doc = {
                "severity":  "HIGH",
                "timestamp": datetime.now().isoformat(),
                "pid":       event.pid,
                "uid":       event.uid,
                "process":   comm,
                "binary":    filename,
                "alerts":    alerts,
            }
            print(f"\n[!!! ALERT !!!] {json.dumps(alert_doc)}\n", file=sys.stderr)
            self.captured_alerts.append(alert_doc)
    def _output_execve_json(self, event: ExecveEvent,
                             comm: str, filename: str) -> None:
        etype = {1: "EXECVE_ENTER", 2: "EXECVE_FAILED"}.get(event.event_type, "UNKNOWN")
        print(json.dumps({
            "type":      etype,
            "timestamp": datetime.fromtimestamp(event.timestamp_ns / 1e9).isoformat(),
            "process": {
                "pid":  event.pid,
                "tgid": event.tgid,
                "uid":  event.uid,
                "gid":  event.gid,
                "name": comm,
            },
            "binary": filename,
            "seq":    self.event_count,
        }))
    def _output_execve_human(self, event: ExecveEvent,
                              comm: str, filename: str) -> None:
        etype = "EXECVE" if event.event_type == self.EVENT_EXECVE_ENTER else "FAIL"
        ts = datetime.fromtimestamp(event.timestamp_ns / 1e9).strftime("%H:%M:%S.%f")[:-3]
        print(f"[{ts}] {etype:5s} | PID={event.pid:<6} TGID={event.tgid:<6} "
              f"UID={event.uid:<5} | {comm:<16} → {filename}")
    def _output_connect_json(self, event: ConnectEvent, ip: str) -> None:
        print(json.dumps({
            "type":      "TCP_CONNECT",
            "timestamp": datetime.now().isoformat(),
            "process": {
                "pid":  event.pid,
                "tgid": event.tgid,
                "uid":  event.uid,
            },
            "destination": {"ip": ip, "port": event.dport},
            "seq":    self.event_count,
        }))
    def _output_connect_human(self, event: ConnectEvent, ip: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{ts}] CONN  | PID={event.pid:<6} TGID={event.tgid:<6} "
              f"UID={event.uid:<5} | → {ip}:{event.dport}")
    def _handle_signal(self, signum: int, frame) -> None:
        print(f"\n[*] Signal {signum} received — shutting down...")
        self._running = False
    def run(self) -> None:
        self._running = True
        mode_str = "SAFE (log-only)" if SAFE_MODE else "LIVE (kill+block)"
        print(f"[*] Zenith-Sentry eBPF Monitor running — mode: {mode_str}")
        print(f"[*] Watchlist ports: {sorted(CRITICAL_PORTS)}")
        print(f"[*] Watchlist bins : {sorted(CRITICAL_BINS)}")
        print("[*] Press Ctrl+C to stop\n")
        try:
            while self._running:
                self.bpf.perf_buffer_poll(timeout=1000)
        except KeyboardInterrupt:
            pass
        finally:
            self._cleanup()
    def _cleanup(self) -> None:
        runtime = time.time() - self.start_time
        eps = self.event_count / runtime if runtime > 0 else 0
        print(f"\n[*] Monitor stopped. Runtime: {runtime:.1f}s | "
              f"Events: {self.event_count} ({eps:.0f}/s) | "
              f"Alerts: {self.alert_count}")
    def get_events(self) -> List[Dict]:
        return self.captured_events[:]
    def get_alerts(self) -> List[Dict]:
        return self.captured_alerts[:]
    def clear_events(self) -> None:
        self.captured_events = []
        self.captured_alerts = []
def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Zenith-Sentry — Kernel eBPF process & network monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 process_execve_monitor.py --source zenith/ebpf/execve_monitor.c
  sudo python3 process_execve_monitor.py --source zenith/ebpf/execve_monitor.c --human
  sudo python3 process_execve_monitor.py --source zenith/ebpf/execve_monitor.c --enforce
        """)
    parser.add_argument("--source",  type=str, required=True,
                        help="Path to BPF C source file")
    parser.add_argument("--human",   action="store_true",
                        help="Human-readable output (default: JSON)")
    parser.add_argument("--enforce", action="store_true",
                        help="Enable live mitigation (kill + iptables) — USE WITH CAUTION")
    parser.add_argument("--debug",   action="store_true",
                        help="Print full tracebacks on errors")
    args = parser.parse_args()
    if not os.path.exists(args.source):
        print(f"[ERROR] BPF source not found: {args.source}")
        sys.exit(1)
    if os.geteuid() != 0:
        print("[ERROR] Root privileges required. Run with sudo.")
        sys.exit(1)
    if not HAS_BCC:
        print("[ERROR] BCC library not installed.")
        print("        apt install python3-bpfcc  OR  pip3 install bcc")
        sys.exit(1)
    try:
        monitor = ProcessExecutionMonitor(
            ebpf_source=args.source,
            enable_json=not args.human,
            safe_mode=not args.enforce,
        )
        monitor.run()
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    except Exception as e:
        print(f"[ERROR] Monitor failed: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)
if __name__ == "__main__":
    main()
