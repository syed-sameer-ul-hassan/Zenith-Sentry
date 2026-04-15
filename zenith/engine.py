"""Zenith-Sentry orchestration engine - coordinates scans and detectors."""

import json
import threading
import os
import datetime
import logging

from zenith.config import ConfigLoader
from zenith.collectors import ProcessCollector, NetworkCollector, SystemCollector
from zenith.registry import PluginRegistry

logger = logging.getLogger(__name__)


class ZenithEngine:
    """Orchestrates the full threat detection pipeline."""
    
    def __init__(self, args):
        """Initialize the detection engine.
        
        Args:
            args: Parsed command-line arguments
        """
        self.args = args
        self.config = ConfigLoader(args.profile)
        self.registry = PluginRegistry()
        self.registry.load_plugins()
        self.ebpf_monitor = None
        self.ebpf_thread = None
    
    def start_ebpf_monitor(self):
        """Start optional eBPF kernel-level process monitoring."""
        if os.geteuid() != 0:
            logger.info("eBPF monitor requires root - skipping")
            return
        
        try:
            from process_execve_monitor import ProcessExecutionMonitor
            
            ebpf_source = os.path.join(
                os.path.dirname(__file__), "ebpf", "execve_monitor.c"
            )
            
            if not os.path.exists(ebpf_source):
                logger.warning(f"eBPF source not found: {ebpf_source}")
                return
            
            self.ebpf_monitor = ProcessExecutionMonitor(
                ebpf_source=ebpf_source,
                enable_json=True
            )
            
            self.ebpf_thread = threading.Thread(
                target=self.ebpf_monitor.run,
                daemon=True,
                name="ZenithEBPFMonitor"
            )
            self.ebpf_thread.start()
            logger.info("eBPF process execution monitor started")
            
        except ImportError:
            logger.warning("BCC library not available - eBPF disabled")
        except Exception as e:
            logger.warning(f"Failed to start eBPF monitor: {e}")
    
    def run_scan(self):
        """Execute full threat detection scan.
        
        Runs:
        1. Telemetry collection (processes, network, system)
        2. Plugin-based threat detection
        3. Risk scoring
        4. Report generation and output
        """
        if hasattr(self.args, 'ebpf') and self.args.ebpf:
            self.start_ebpf_monitor()
        
        logger.info("Starting threat detection scan...")
        
        try:
            logger.debug("Collecting process telemetry...")
            procs = ProcessCollector().collect()
            logger.debug(f"Collected {len(procs)} processes")
            
            logger.debug("Collecting network telemetry...")
            conns = NetworkCollector().collect()
            
            logger.debug("Collecting system telemetry...")
            sys_files = SystemCollector(
                self.config.get("persistence", {}).get("scan_dirs", [])
            ).collect()
            
            logger.debug("Instantiating detectors...")
            detectors = self.registry.instantiate(
                procs=procs,
                conns=conns,
                sys_files=sys_files,
                config=self.config.config
            )
            logger.debug(f"Running {len(detectors)} detectors...")
            
            findings = []
            for detector in detectors:
                try:
                    detector_findings = detector.analyze()
                    findings.extend(detector_findings)
                except Exception as e:
                    logger.error(f"Detector {detector.name} failed: {e}")
            
            logger.info(f"Detection complete: {len(findings)} findings")
            
            if findings:
                score = min(
                    int(sum(f.risk.value for f in findings) / len(findings)),
                    100
                )
            else:
                score = 0
            
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            os.makedirs("user_data", exist_ok=True)
            
            report_data = {
                "score": score,
                "timestamp": timestamp,
                "findings": [
                    {
                        "id": f.id,
                        "module": f.module,
                        "risk": f.risk.name,
                        "severity": f.severity.name,
                        "tactic": f.tactic,
                        "description": f.description,
                        "evidence": f.evidence
                    }
                    for f in findings
                ]
            }
            
            report_path = f"user_data/scan_{timestamp}.json"
            with open(report_path, "w") as f:
                json.dump(report_data, f, indent=2)
            
            logger.info(f"Report saved to {report_path}")
            
            if self.args.json:
                print(json.dumps(report_data))
            else:
                self._print_human_readable(score, findings)
        
        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            raise
    
    def _print_human_readable(self, score, findings):
        """Print human-readable scan results.
        
        Args:
            score: Risk score (0-100)
            findings: List of Finding objects
        """
        print(f"\n{'='*50}")
        print(f"ZENITH-SENTRY Scan Results")
        print(f"{'='*50}")
        print(f"Risk Score: {score}/100")
        
        if not findings:
            print("\nNo threats detected!")
            return
        
        threshold = getattr(self.args, 'risk_threshold', 0)
        filtered = [f for f in findings if f.risk.value >= threshold]
        
        if not filtered:
            print(f"\nNo findings above threshold ({threshold})")
            return
        
        print(f"\nFindings ({len(filtered)}):\n")
        for idx, finding in enumerate(filtered, 1):
            print(f"[{idx}] {finding.risk.name} | {finding.tactic}")
            print(f"    Module: {finding.module}")
            print(f"    Description: {finding.description}")
            if finding.evidence:
                print(f"    Evidence: {finding.evidence}")
            print()

