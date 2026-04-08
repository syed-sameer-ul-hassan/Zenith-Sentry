# 🛡️ Zenith-Sentry EDR Agent

Production-grade Host-Based Intrusion Detection and Forensic Toolkit. 
Zenith-Sentry is designed with an "Assume Breach" philosophy, mapping runtime anomalies directly to MITRE ATT&CK tactics.

## Architecture
* **Collectors**: Gather telemetry safely from `/proc`, `/sys`, and network sockets.
* **Detectors**: Apply heuristic and rule-based logic to detect C2, execution, and persistence.
* **FIM Engine**: Multi-processed SHA-256 file integrity monitor.
* **Risk Engine**: Calculates weighted scores to classify threats.
# Zenith-Sentry
