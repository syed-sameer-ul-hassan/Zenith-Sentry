#!/usr/bin/env python3
"""Zenith-Sentry CLI interface - Linux EDR with eBPF kernel monitoring."""

import argparse
import sys
import os
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from zenith.engine import ZenithEngine

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Zenith-Sentry: Linux EDR with eBPF Kernel Monitoring",
        epilog="Examples:\n"
               "  python3 main.py full-scan\n"
               "  python3 main.py full-scan --json\n"
               "  sudo python3 main.py full-scan --ebpf",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "command",
        choices=["full-scan", "network", "process", "persistence", "fim", "hunt"],
        help="Scan type to execute"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON (for SIEM integration)"
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=os.path.join(os.path.dirname(__file__), "config.yaml"),
        help="Path to YAML configuration file"
    )
    parser.add_argument(
        "--risk-threshold",
        type=int,
        default=0,
        choices=[0, 25, 50, 75, 100],
        help="Minimum risk level to display (0=INFO, 25=LOW, 50=MEDIUM, 75=HIGH, 100=CRITICAL)"
    )
    parser.add_argument(
        "--ebpf",
        action="store_true",
        help="Enable eBPF kernel-level process execution monitoring (requires root)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        engine = ZenithEngine(args)
        engine.run_scan()
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()

