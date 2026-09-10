from app.detectors.base import BaseDetector, FindingData
from app.detectors.registry import run_all_detectors, DEFAULT_DETECTORS
from app.detectors.identity_spoofing import IdentitySpoofingDetector
from app.detectors.auth_failure import AuthFailureDetector
from app.detectors.suspicious_attachment import SuspiciousAttachmentDetector
from app.detectors.suspicious_url import SuspiciousUrlDetector
from app.detectors.bec_intent import BecIntentDetector

__all__ = [
    "BaseDetector",
    "FindingData",
    "run_all_detectors",
    "DEFAULT_DETECTORS",
    "IdentitySpoofingDetector",
    "AuthFailureDetector",
    "SuspiciousAttachmentDetector",
    "SuspiciousUrlDetector",
    "BecIntentDetector",
]
