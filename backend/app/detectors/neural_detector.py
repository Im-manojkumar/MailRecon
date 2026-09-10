"""
Neural Sequence Phishing Detector using 1D-CNN + Bi-GRU hybrid deep learning architecture.
Analyzes email subject and body for linguistic coercion, credential theft lures, and deceptive patterns.
"""
from typing import List, Optional

from app.detectors.base import BaseDetector, FindingData
from app.ml.classifier import PhishingNeuralClassifier, get_neural_classifier
from app.models.finding import SeverityLevel
from app.parser.email_parser import ParsedEmailResult


class NeuralSequenceDetector(BaseDetector):
    name = "neural_1dcnn_bigru"

    def __init__(self, classifier: Optional[PhishingNeuralClassifier] = None):
        self._classifier = classifier

    @property
    def classifier(self) -> PhishingNeuralClassifier:
        if self._classifier is None:
            self._classifier = get_neural_classifier()
        return self._classifier

    def analyze(self, parsed: ParsedEmailResult) -> List[FindingData]:
        findings: List[FindingData] = []

        if not self.classifier.is_ready:
            return findings

        # Combine subject and body text for linguistic sequence analysis
        subject = parsed.headers.get("Subject", "")
        body = parsed.body_text or ""
        text = f"{subject}\n\n{body}".strip()

        if not text:
            return findings

        prediction = self.classifier.predict(text)
        if not prediction or not prediction.is_phishing:
            return findings

        # Map risk level to SeverityLevel
        if prediction.risk_level == "critical":
            severity = SeverityLevel.critical
        elif prediction.risk_level == "high":
            severity = SeverityLevel.high
        else:
            severity = SeverityLevel.medium

        # Build grounded forensic explanation
        salient_desc = ""
        if prediction.salient_tokens:
            quoted_tokens = ", ".join(f"'{t}'" for t in prediction.salient_tokens)
            salient_desc = f" High-salience trigger cues identified: {quoted_tokens}."

        detail = (
            f"1D-CNN + Bi-GRU neural sequence model detected phishing patterns with "
            f"{prediction.probability * 100:.1f}% probability."
            f"{salient_desc} The textual sequence exhibits structural coercion and attack characteristics."
        )

        evidence_ref = "body_text" if body else "headers.Subject"

        findings.append(
            FindingData(
                detector=self.name,
                severity=severity,
                title=f"Neural Linguistic Analysis: Phishing Patterns ({prediction.probability * 100:.1f}%)",
                detail=detail,
                evidence_ref=evidence_ref,
                confidence=round(prediction.probability, 2),
                raw_evidence={
                    "model": "1dcnn_bigru",
                    "phishing_probability": round(prediction.probability, 4),
                    "confidence": round(prediction.confidence, 4),
                    "salient_tokens": prediction.salient_tokens,
                    "architecture": "Embedding(128) -> Conv1D(128, k=3) -> Bi-GRU(64) -> GlobalMaxPool -> Dense",
                },
            )
        )

        return findings
