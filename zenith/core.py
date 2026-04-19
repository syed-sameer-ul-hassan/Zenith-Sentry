import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, Any, List, Optional
class RiskLevel(IntEnum):
    INFO = 0
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    CRITICAL = 100
class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    module: str = "Unknown"
    risk: RiskLevel = RiskLevel.INFO
    severity: Severity = Severity.LOW
    tactic: str = "Unknown"
    description: str = "No description"
    evidence: Dict[str, Any] = field(default_factory=dict)
    def __post_init__(self):
        if not isinstance(self.risk, RiskLevel):
            raise TypeError(f"risk must be RiskLevel, got {type(self.risk)}")
        if not isinstance(self.severity, Severity):
            raise TypeError(f"severity must be Severity, got {type(self.severity)}")
        if not isinstance(self.evidence, dict):
            raise TypeError(f"evidence must be dict, got {type(self.evidence)}")
class IDetector:
    name: str = "BaseDetector"
    def analyze(self) -> List[Finding]:
        raise NotImplementedError("Subclasses must implement analyze()")
