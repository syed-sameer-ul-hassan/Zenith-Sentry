import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from datetime import datetime
from typing import Dict, Any, List

class RiskLevel(IntEnum): INFO=0; LOW=25; MEDIUM=50; HIGH=75; CRITICAL=100
class Severity(IntEnum): LOW=1; MEDIUM=2; HIGH=3; CRITICAL=4

@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    module: str = "Unknown"
    risk: RiskLevel = RiskLevel.INFO
    severity: Severity = Severity.LOW
    tactic: str = "Unknown"
    description: str = "No description"
    evidence: Dict[str, Any] = field(default_factory=dict)

class IDetector:
    name: str = "Base"
    def analyze(self) -> List[Finding]: return []
