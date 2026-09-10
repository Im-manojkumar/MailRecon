from typing import List

from app.detectors.auth_failure import AuthFailureDetector
from app.detectors.base import BaseDetector, FindingData
from app.detectors.bec_intent import BecIntentDetector
from app.detectors.identity_spoofing import IdentitySpoofingDetector
from app.detectors.neural_detector import NeuralSequenceDetector
from app.detectors.suspicious_attachment import SuspiciousAttachmentDetector
from app.detectors.suspicious_url import SuspiciousUrlDetector
from app.parser.email_parser import ParsedEmailResult

DEFAULT_DETECTORS: List[BaseDetector] = [
    IdentitySpoofingDetector(),
    AuthFailureDetector(),
    SuspiciousAttachmentDetector(),
    SuspiciousUrlDetector(),
    BecIntentDetector(),
    NeuralSequenceDetector(),
]


def run_all_detectors(
    parsed: ParsedEmailResult,
    detectors: List[BaseDetector] | None = None
) -> List[FindingData]:
    """Execute all configured detectors on the parsed email and return all findings."""
    active_detectors = detectors or DEFAULT_DETECTORS
    all_findings: List[FindingData] = []

    for detector in active_detectors:
        try:
            results = detector.analyze(parsed)
            all_findings.extend(results)
        except Exception as e:
            # Failure in one detector must never abort the whole analysis
            import logging
            logging.getLogger(__name__).warning(f"Detector {detector.name} failed: {e}")

    return all_findings
