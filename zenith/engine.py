import json
from zenith.config import ConfigLoader
from zenith.collectors import ProcessCollector, NetworkCollector, SystemCollector
from zenith.registry import PluginRegistry

class ZenithEngine:
    def __init__(self, args):
        self.args = args
        self.config = ConfigLoader(args.profile)
        self.registry = PluginRegistry()
        self.registry.load_plugins()

    def run_scan(self):
        procs = ProcessCollector().collect()
        conns = NetworkCollector().collect()
        sys_files = SystemCollector(self.config.get("persistence", {}).get("scan_dirs", [])).collect()
        
        detectors = self.registry.instantiate(procs=procs, conns=conns, sys_files=sys_files, config=self.config.config)
        findings = []
        for det in detectors: findings.extend(det.analyze())
            
        score = min(int(sum(f.risk.value for f in findings) / len(findings)) if findings else 0, 100)
        
        # Save data to auto-created user_data folder
        import os, datetime
        os.makedirs("user_data", exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_data = {
            "score": score,
            "timestamp": timestamp,
            "findings": [{"id": f.id, "module": f.module, "risk": f.risk.name, "severity": f.severity.name, "tactic": f.tactic, "description": f.description, "evidence": f.evidence} for f in findings]
        }
        
        with open(f"user_data/scan_{timestamp}.json", "w") as f:
            json.dump(report_data, f, indent=2)
            
        if self.args.json: print(json.dumps(report_data))
        else:
            print(f"\n=== ZENITH-SENTRY ===")
            print(f"Score: {score}/100")
            for idx, f in enumerate(findings, 1):
                if f.risk.value >= self.args.risk_threshold:
                    print(f"\n[{idx}] {f.risk.name} | {f.tactic} | {f.description}\n    {f.evidence}")
