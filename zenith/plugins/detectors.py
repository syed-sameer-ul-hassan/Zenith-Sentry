from zenith.core import IDetector, Finding, RiskLevel, Severity
class ProcessDetector(IDetector):
    name = "ProcessAnalysis"
    def __init__(self, procs, **kwargs): self.procs = procs
    def analyze(self):
        findings = []
        for pid, info in self.procs.items():
            cmd = " ".join(info.get('cmdline') or "")
            if "curl " in cmd and "| bash" in cmd:
                findings.append(Finding(module=self.name, risk=RiskLevel.CRITICAL, severity=Severity.CRITICAL, tactic="Execution", description="Suspicious pipeline", evidence={"pid": pid, "cmd": cmd}))
        return findings
