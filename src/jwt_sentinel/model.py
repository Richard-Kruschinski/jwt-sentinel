from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    id: str
    title: str
    severity: str  # "low", "medium", "high"
    description: str
    recommendation: str


@dataclass
class AnalysisResult:
    token: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    algorithm: Optional[str]
    signature_valid: Optional[bool]
    findings: List[Finding] = field(default_factory=list)
    score: int = 0
