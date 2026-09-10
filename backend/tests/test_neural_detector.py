import pytest
from app.detectors.neural_detector import NeuralSequenceDetector
from app.ml.classifier import PhishingNeuralClassifier, get_neural_classifier
from app.ml.tokenizer import PhishingTokenizer
from app.parser.email_parser import ParsedEmailResult


def test_tokenizer_entity_normalization():
    tokenizer = PhishingTokenizer(max_length=32)
    tokenizer.build_vocab(["hello world", "wire transfer of $10,000 to user@example.com at https://evil.com"])

    text = "Send $5,000 to ceo@firm.com via http://portal.xyz now!"
    normalized = tokenizer.normalize_text(text)
    assert "<money>" in normalized or "<MONEY>" in normalized
    assert "<email>" in normalized or "<EMAIL>" in normalized
    assert "<url>" in normalized or "<URL>" in normalized

    encoded = tokenizer.encode(text)
    assert len(encoded) == 32
    assert encoded[-1] == tokenizer.pad_id

    decoded = tokenizer.decode(encoded)
    assert "<money>" in decoded or "<MONEY>" in decoded


def test_neural_classifier_phishing_vs_benign():
    classifier = get_neural_classifier()
    assert classifier.is_ready is True

    # 1. Obvious phishing lure
    phishing_text = (
        "URGENT: Your Microsoft 365 account has been suspended due to suspicious logins. "
        "Verify your credentials at https://login.ms-security-portal.xyz/verify immediately "
        "or access will be terminated."
    )
    pred_phish = classifier.predict(phishing_text)
    assert pred_phish is not None
    assert pred_phish.is_phishing is True
    assert pred_phish.probability >= 0.5
    assert len(pred_phish.salient_tokens) > 0

    # 2. Obvious benign corporate correspondence
    benign_text = (
        "Are we still on for the project review meeting tomorrow at 10 AM in Conference Room B? "
        "Looking forward to catching up on sprint velocity."
    )
    pred_benign = classifier.predict(benign_text)
    assert pred_benign is not None
    assert pred_benign.is_phishing is False
    assert pred_benign.probability < 0.5

    # 3. Empty text handling
    pred_empty = classifier.predict("")
    assert pred_empty is not None
    assert pred_empty.is_phishing is False


def test_neural_detector_analyze():
    detector = NeuralSequenceDetector()
    assert detector.name == "neural_1dcnn_bigru"

    # Phishing email parsed representation
    phishing_parsed = ParsedEmailResult(
        headers={"Subject": "Urgent: Wire Transfer of $45,000 Needed"},
        body_text="Please process an immediate wire transfer of $45,000. Confidential, do not discuss.",
        body_html="",
        raw_html="",
        blocked_images=[],
        attachments=[],
        urls=[],
        auth_results={},
        received_chain=[],
    )

    findings = detector.analyze(phishing_parsed)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector == "neural_1dcnn_bigru"
    assert finding.evidence_ref == "body_text"
    assert finding.confidence >= 0.5
    assert "1D-CNN + Bi-GRU" in finding.detail
    assert finding.raw_evidence["model"] == "1dcnn_bigru"

    # Clean email parsed representation
    clean_parsed = ParsedEmailResult(
        headers={"Subject": "Weekly Engineering Sync Notes"},
        body_text="Here are the notes from today's sprint standup. Velocity is healthy.",
        body_html="",
        raw_html="",
        blocked_images=[],
        attachments=[],
        urls=[],
        auth_results={},
        received_chain=[],
    )

    clean_findings = detector.analyze(clean_parsed)
    assert len(clean_findings) == 0
