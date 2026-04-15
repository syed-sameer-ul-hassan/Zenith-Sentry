#!/usr/bin/env python3
"""
Production-ready eBPF-based process execution monitor.
Hooks sys_execve at kernel level for system-wide process tracking.

Security Features:
- Kernel-level visibility (userspace rootkits cannot hide)
- Lock-free event streaming via ring buffer
- Real-time alerting with structured JSON output
- Graceful signal handling and cleanup
"""

import ctypes
import signal
import sys
import json
import time
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

try:
    from bcc import BPF, RING_BUFFER_OUTPUT
except ImportError:
    print("[ERROR] BCC library not found. Install: pip3 install bcc")
    sys.exit(1)


class ExecveEvent(ctypes.Structure):
    """Kernel event structure for execve monitoring."""
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
        ("timestamp_ns", ctypes.c_uint64),
        ("event_type", ctypes.c_uint8),
    ]


class ProcessExecutionMonitor:
    """eBPF manager for kernel-level process execution tracking."""
    
    EVENT_EXECVE_ENTER = 1
    EVENT_EXECVE_FAILED = 2
    
    EVENT_BATCH_SIZE = 10
    JSON_OUTPUT = True
    ALERT_THRESHOLD_UID = 0
    
    def __init__(self, ebpf_source: str, enable_json: bool = True):
        """
        Initialize the eBPF monitor.
        
        Args:
            ebpf_source: Path to the C eBPF program file
            enable_json: Output events as JSON (vs. human-readable)
        """
        self.ebpf_source = ebpf_source
        self.json_output = enable_json
        self.event_count = 0
        self.start_time = time.time()
        self.bpf = None
        self.ring_buffer = None
        self._running = False
        
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        
        self._load_ebpf()
    
    def _load_ebpf(self) -> None:
        """Load eBPF program from source file."""
        try:
            with open(self.ebpf_source, 'r') as f:
                program_text = f.read()
        except FileNotFoundError:
            print(f"[ERROR] eBPF source not found: {self.ebpf_source}")
            sys.exit(1)
        
        try:
            self.bpf = BPF(text=program_text)
            print("[+] eBPF program loaded and verified")
        except Exception as e:
            print(f"[ERROR] Failed to compile eBPF: {e}")
            sys.exit(1)
        
        try:
            self.bpf.attach_tracepoint(tp="syscalls:sys_enter_execve",
                                       fn_name="tracepoint__syscalls__sys_enter_execve")
            self.bpf.attach_tracepoint(tp="syscalls:sys_exit_execve",
                                       fn_name="tracepoint__syscalls__sys_exit_execve")
            print("[+] Tracepoints attached (syscalls:sys_enter_execve, sys_exit_execve)")
        except Exception as e:
            print(f"[ERROR] Failed to attach tracepoints: {e}")
            sys.exit(1)
        
        try:
            self.ring_buffer = self.bpf["events"].open_ring_buffer(
                self._handle_event
            )
            print("[+] Ring buffer opened (lock-free event streaming)")
        except (KeyError, AttributeError):
            print("[!] Ring buffer unavailable; falling back to perf buffer")
            self.bpf["event_table"].open_perf_buffer(self._handle_event)
    
    def _handle_event(self, ctx, data: bytes, size: int) -> None:
        """
        Event callback from kernel (per-event handler).
        
        Args:
            ctx: Ring buffer context
            data: Raw event bytes
            size: Event size
        """
        event = ctypes.cast(data, ctypes.POINTER(ExecveEvent)).contents
        self.event_count += 1
        
        try:
            comm = event.comm.decode('utf-8', errors='replace').strip('\x00')
            filename = event.filename.decode('utf-8', errors='replace').strip('\x00')
        except Exception as e:
            print(f"[WARN] Failed to decode event: {e}")
            return
        
        if self.json_output:
            self._output_json(event, comm, filename)
        else:
            self._output_human(event, comm, filename)
        
        self._threat_heuristics(event, comm, filename)
    
    def _output_json(self, event: ExecveEvent, comm: str, filename: str) -> None:
        """Output event as JSON for SIEM/tooling integration."""
        event_dict = {
            "timestamp": datetime.fromtimestamp(event.timestamp_ns / 1e9).isoformat(),
            "event_type": ["EXECVE_ENTER", "EXECVE_FAILED"][event.event_type - 1],
            "process": {
                "pid": event.pid,
                "ppid": event.ppid,
                "uid": event.uid,
                "gid": event.gid,
                "name": comm,
            },
            "execution": {
                "binary": filename,
            },
            "sequence_number": self.event_count,
        }
        print(json.dumps(event_dict))
    
    def _output_human(self, event: ExecveEvent, comm: str, filename: str) -> None:
        """Output event in human-readable format."""
        event_type = "EXECVE" if event.event_type == self.EVENT_EXECVE_ENTER else "FAIL"
        timestamp = datetime.fromtimestamp(event.timestamp_ns / 1e9).strftime("%H:%M:%S.%f")[:-3]
        print(f"[{timestamp}] {event_type:5s} | PID={event.pid:5d} "
              f"UID={event.uid:5d} | {comm:15s} → {filename}")
    
    def _threat_heuristics(self, event: ExecveEvent, comm: str, filename: str) -> None:
        """
        Apply lightweight threat detection heuristics.
        Flagged events are logged separately.
        """
        alerts = []
        
        if event.uid == 0 and event.event_type == self.EVENT_EXECVE_ENTER:
            alerts.append(f"Root process execution: {comm}")
        
        if filename.startswith(("/tmp/", "/dev/shm/", "/var/tmp/")):
            alerts.append(f"Binary in suspicious location: {filename}")
        
        if event.event_type == self.EVENT_EXECVE_FAILED:
            alerts.append(f"Execve failure for {filename} (possible evasion)")
        
        if alerts:
            alert_output = {
                "severity": "HIGH",
                "timestamp": datetime.now().isoformat(),
                "pid": event.pid,
                "uid": event.uid,
                "process": comm,
                "binary": filename,
                "alerts": alerts,
            }
            print(f"\n[!!! ALERT !!!] {json.dumps(alert_output)}\n", file=sys.stderr)
    
    def _handle_signal(self, signum: int, frame) -> None:
        """Graceful shutdown handler."""
        print(f"\n[*] Received signal {signum}. Shutting down...")
        self._running = False
    
    def run(self) -> None:
        """
        Start monitoring loop (blocks until signal).
        
        Call this function to begin real-time monitoring.
        """
        self._running = True
        print("[*] Process execution monitor started (PID monitoring active)")
        print("[*] Press Ctrl+C to stop\n")
        
        try:
            while self._running:
                if self.ring_buffer:
                    self.ring_buffer.poll(timeout=1000)
                else:
                    self.bpf.perf_buffer_poll(timeout=1000)
        
        except KeyboardInterrupt:
            pass
        finally:
            self._cleanup()
    
    def _cleanup(self) -> None:
        """Cleanup and statistics."""
        runtime_sec = time.time() - self.start_time
        events_per_sec = self.event_count / runtime_sec if runtime_sec > 0 else 0
        
        print(f"\n[*] Statistics:")
        print(f"    Total events: {self.event_count}")
        print(f"    Runtime: {runtime_sec:.1f}s")
        print(f"    Throughput: {events_per_sec:.0f} events/sec")



def main():
    """CLI entrypoint with argument parsing."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Kernel-level process execution monitor using eBPF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 process_execve_monitor.py --source zenith/ebpf/execve_monitor.c
  sudo python3 process_execve_monitor.py --source zenith/ebpf/execve_monitor.c --human
  sudo python3 process_execve_monitor.py --source zenith/ebpf/execve_monitor.c --debug
        """)
    
    parser.add_argument('--source', type=str, required=True,
                        help='Path to eBPF C source file')
    parser.add_argument('--human', action='store_true',
                        help='Output in human-readable format (default: JSON)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug output')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.source):
        print(f"[ERROR] eBPF source file not found: {args.source}")
        sys.exit(1)
    
    if os.geteuid() != 0:
        print("[ERROR] This tool requires root privileges (for kernel probe attachment)")
        print("        Run with: sudo python3 process_execve_monitor.py ...")
        sys.exit(1)
    
    try:
        monitor = ProcessExecutionMonitor(
            ebpf_source=args.source,
            enable_json=not args.human
        )
        monitor.run()
    except KeyboardInterrupt:
        print("\n[*] Monitor interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Monitor failed: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
