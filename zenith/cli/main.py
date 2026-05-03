#!/usr/bin/env python3
"""
Command-line interface for Zenith-Sentry.
"""
import argparse
import sys
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from zenith.engine import ZenithEngine
from zenith.config import ConfigLoader

logger = logging.getLogger(__name__)

def cmd_full_scan(args):
    """Run a full security scan."""
    print("Starting full security scan...")
    
    config = ConfigLoader(args.config)
    engine = ZenithEngine(config.config, ebpf_enabled=args.ebpf)
    
    procs, conns, sys_files = engine._collect_telemetry()
    detectors = engine.registry.instantiate(
        procs=procs,
        conns=conns,
        sys_files=sys_files,
        ebpf_events=[],
        config=config.config
    )
    
    findings = []
    for detector in detectors:
        findings.extend(detector.detect())
    
    print(f"Scan complete. Found {len(findings)} findings.")
    
    if args.output:
        engine._generate_report(findings, len(findings), args.output)
        print(f"Report saved to {args.output}")
    
    return 0

def cmd_quick_scan(args):
    """Run a quick security scan."""
    print("Starting quick security scan...")
    
    config = ConfigLoader(args.config)
    engine = ZenithEngine(config.config, ebpf_enabled=False)
    
    procs, conns, sys_files = engine._collect_telemetry()
    detectors = engine.registry.instantiate(
        procs=procs,
        conns=conns,
        sys_files=sys_files,
        ebpf_events=[],
        config=config.config
    )
    
    findings = []
    for detector in detectors:
        findings.extend(detector.detect())
    
    print(f"Quick scan complete. Found {len(findings)} findings.")
    
    return 0

def cmd_status(args):
    """Show system status."""
    print("Zenith-Sentry Status")
    print("==================")
    
    config = ConfigLoader(args.config)
    
    print(f"Config file: {args.config}")
    print(f"Config loaded: {bool(config.config)}")
    
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        print(f"\nSystem Resources:")
        print(f"  CPU: {cpu}%")
        print(f"  Memory: {memory.percent}%")
    except ImportError:
        print("\npsutil not installed, skipping resource check")
    
    return 0

def cmd_version(args):
    """Show version information."""
    print("Zenith-Sentry v0.1.0")
    print("Linux Endpoint Detection and Response (EDR) Tool")
    return 0

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Zenith-Sentry - Linux EDR Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--config",
        "-c",
        default="config.yaml",
        help="Path to configuration file"
    )
    
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    scan_parser = subparsers.add_parser("full-scan", help="Run a full security scan")
    scan_parser.add_argument("--ebpf", action="store_true", help="Enable eBPF monitoring")
    scan_parser.add_argument("--output", "-o", help="Output file for report")
    scan_parser.set_defaults(func=cmd_full_scan)
    
    quick_parser = subparsers.add_parser("quick-scan", help="Run a quick security scan")
    quick_parser.set_defaults(func=cmd_quick_scan)
    
    status_parser = subparsers.add_parser("status", help="Show system status")
    status_parser.set_defaults(func=cmd_status)
    
    version_parser = subparsers.add_parser("version", help="Show version information")
    version_parser.set_defaults(func=cmd_version)
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    if args.command:
        return args.func(args)
    else:
        parser.print_help()
        return 0

if __name__ == "__main__":
    sys.exit(main())
