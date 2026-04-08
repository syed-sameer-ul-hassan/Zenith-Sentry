import argparse, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from zenith.engine import ZenithEngine

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["full-scan", "network", "process", "persistence", "fim", "hunt"])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--profile", type=str, default=os.path.join(os.path.dirname(__file__), "config.yaml"))
    parser.add_argument("--risk-threshold", type=int, default=0)
    args = parser.parse_args()
    ZenithEngine(args).run_scan()

if __name__ == "__main__":
    main()
