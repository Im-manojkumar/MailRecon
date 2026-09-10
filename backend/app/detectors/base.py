from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.models.finding import SeverityLevel
from app.parser.email_parser import ParsedEmailResult


@dataclass
class FindingData:
    detector: str
    severity: SeverityLevel
    title: str
    detail: str
    evidence_ref: str
    confidence: float  # 0.0 to 1.0 heuristic confidence
    raw_evidence: Dict[str, Any] = field(default_factory=dict)


class BaseDetector(ABC):
    """Abstract base class for all deterministic threat detectors."""
    name: str

    @abstractmethod
    def analyze(self, parsed: ParsedEmailResult) -> List[FindingData]:
        """Analyze a parsed email and return zero or more grounded findings."""
        pass
