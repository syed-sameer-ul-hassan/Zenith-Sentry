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
        
        if self.args.json: print(json.dumps({"score": score, "findings": [f.__dict__ for f in findings]}))
        else:
            print(f"\n=== ZENITH-SENTRY ===")
            print(f"Score: {score}/100")
            for idx, f in enumerate(findings, 1):
                if f.risk.value >= self.args.risk_threshold:
                    print(f"\n[{idx}] {f.risk.name} | {f.tactic} | {f.description}\n    {f.evidence}")
