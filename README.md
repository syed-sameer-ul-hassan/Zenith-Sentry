<p align="center">
  <img src="logo.svg" alt="Zenith-Sentry Logo" width="200"/>
</p>

<h1 align="center">Zenith-Sentry EDR</h1>

<p align="center">
  <i>A Production-Grade, Lightweight Host-Based Intrusion Detection and Forensic Toolkit for Linux.</i>
</p>

---

##  Overview
`
Zenith-Sentry is designed with an "Assume Breach" philosophy. Instead of relying purely on static signatures, it actively hunts for behavioral anomalies, in-memory execution, and obscure persistence mechanisms, mapping all findings directly to the MITRE ATT&CK framework.
`

##  Core Architecture
The agent is built on a highly modular, decoupled architecture:
* Collectors (`zenith/collectors.py`) : Exception-safe telemetry gatherers that interface with `/proc`, network namespaces, and the filesystem.
* Detector Registry (`zenith/registry.py`) : A dynamic plugin loader. Drop a new Python script into the `plugins/` directory, and the engine auto-loads it.
* Risk Engine (`zenith/engine.py`) : Calculates aggregate host risk (0-100) based on finding severity and frequency.
* Observability : Automatically tracks scan duration, finding yields per module, and internal plugin errors.

---

##  Feature Breakdown

### 1. Process & Execution Detection (`ProcessAnalysis`)
Monitors the process tree for defense evasion and malicious execution.
* **Volatile Execution (T1059)**: Detects binaries executing directly from memory-backed or temporary file systems (`/tmp`, `/dev/shm`).
* **Deleted Binary Execution (T1070.004)**: Identifies processes running from an inode that has been unlinked from the filesystem (a classic rootkit/malware evasion tactic).
* **Suspicious Pipelines (T1059.004)**: Uses regex heuristics on command lines to catch fileless execution techniques (e.g., `curl x | bash`, `nc -e`).

### 2. Network Anomaly Detection (`NetworkAnalysis`)
Analyzes active TCP/UDP sockets to uncover exfiltration and Command & Control (C2).
* **Malicious Port Profiling (T1071)**: Flags outbound connections to known high-risk ports often used by default C2 frameworks (e.g., 4444, 1337).
* **Interactive Shell Binding (T1059)**: Detects standard scripting interpreters (`bash`, `sh`, `python`) establishing direct external socket connections (Reverse Shells).
* **Loopback Filtering**: Configurable ignore rules for local `127.0.0.1` traffic to reduce false positives.

### 3. Persistence Discovery (`PersistenceAnalysis`)
Scans critical Linux startup mechanisms for hidden backdoors.
* **World-Writable Startup Files (T1546)**: Identifies systemd units, cron jobs, or `.bashrc` files that can be modified by unprivileged users.
* **Temporary Directory Abuse (T1053)**: Flags persistence mechanisms attempting to execute payloads located in `/tmp` or `/dev/shm`.
* **Deep Scanning**: Evaluates `/etc/crontab`, `/etc/cron.d`, systemd services, SSH `authorized_keys`, and user profiles.

### 4. File Integrity Monitoring (FIM)
Calculates SHA-256 hashes of critical system binaries to detect unauthorized modifications or replacements. *(Note: FIM requires baseline creation via the CLI before comparison).*


##  CLI Usage
Zenith-Sentry is operated via a unified command-line interface.


Run a complete system sweep
 ```
zenith-sentry full-scan
```
Output findings in JSON format for SIEM ingestion
```
zenith-sentry full-scan --json
```
Run a targeted hunt for network anomalies only
```
zenith-sentry network --verbose
```
Filter out low-risk noise (only report findings above a score of 50)
```
zenith-sentry process --risk-threshold 50
```
