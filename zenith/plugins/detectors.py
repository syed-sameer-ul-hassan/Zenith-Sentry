"""Built-in threat detectors for Zenith-Sentry."""

import re
import logging
from zenith.core import IDetector, Finding, RiskLevel, Severity

logger = logging.getLogger(__name__)


class ProcessDetector(IDetector):
    """Detects suspicious process execution patterns.
    
    MITRE ATT&CK Coverage:
    - T1059: Command and Scripting Interpreter
    - T1218: Signed Binary Proxy Execution
    """
    
    name = "ProcessExecution"
    
    DEFAULT_PATTERNS = [
        (r'curl\s+.*\|\s*bash', RiskLevel.CRITICAL, Severity.CRITICAL, "curl piped to bash"),
        (r'curl\s+.*\|\s*sh', RiskLevel.CRITICAL, Severity.CRITICAL, "curl piped to shell"),
        (r'wget\s+.*\|\s*bash', RiskLevel.CRITICAL, Severity.CRITICAL, "wget piped to bash"),
        (r'wget\s+.*\|\s*sh', RiskLevel.CRITICAL, Severity.CRITICAL, "wget piped to shell"),
        (r'\|\s*bash\s*$', RiskLevel.HIGH, Severity.HIGH, "Command piped to bash"),
        (r'\|\s*sh\s*$', RiskLevel.HIGH, Severity.HIGH, "Command piped to shell"),
        (r'base64\s+-d', RiskLevel.HIGH, Severity.HIGH, "Base64 decoding (possible obfuscation)"),
        (r'echo.*\|\s*base64', RiskLevel.HIGH, Severity.HIGH, "Base64 encoding in pipeline"),
        (r'\$\(.*\)', RiskLevel.MEDIUM, Severity.MEDIUM, "Command substitution detected"),
        (r'`.*`', RiskLevel.MEDIUM, Severity.MEDIUM, "Backtick command substitution"),
    ]
    
    def __init__(self, procs=None, config=None, **kwargs):
        """Initialize process detector.
        
        Args:
            procs: Dict of processes from ProcessCollector
            config: Configuration dictionary (optional)
        """
        self.procs = procs or {}
        self.config = config or {}
        self.patterns = self.config.get('patterns', self.DEFAULT_PATTERNS)
    
    def analyze(self):
        """Analyze processes for suspicious patterns.
        
        Returns:
            list: Findings for suspicious processes
        """
        findings = []
        
        if not self.procs:
            logger.debug("No processes to analyze")
            return findings
        
        for pid, info in self.procs.items():
            try:
                cmdline = info.get('cmdline')
                if not cmdline:
                    continue
                
                if isinstance(cmdline, list):
                    cmd = " ".join(str(arg) for arg in cmdline)
                elif isinstance(cmdline, str):
                    cmd = cmdline
                else:
                    continue
                
                for pattern, risk, severity, description in self.patterns:
                    try:
                        if re.search(pattern, cmd, re.IGNORECASE):
                            findings.append(Finding(
                                module=self.name,
                                risk=risk,
                                severity=severity,
                                tactic="Execution",
                                description=f"Suspicious {description}",
                                evidence={
                                    "pid": pid,
                                    "process_name": info.get('name', 'unknown'),
                                    "cmdline": cmd[:512],
                                    "pattern": description
                                }
                            ))
                            break
                    except re.error as e:
                        logger.warning(f"Regex error in pattern '{pattern}': {e}")
                        continue
            
            except Exception as e:
                logger.debug(f"Error analyzing process {pid}: {e}")
                continue
        
        logger.info(f"ProcessDetector found {len(findings)} suspicious processes")
        return findings

