import pytest

from app.detectors import (
    run_all_detectors,
    IdentitySpoofingDetector,
    AuthFailureDetector,
    SuspiciousAttachmentDetector,
    SuspiciousUrlDetector,
    BecIntentDetector,
)
from app.models.finding import SeverityLevel
from app.parser.email_parser import EmailParser, AttachmentData
from tests.conftest import fixture_path


def test_detectors_clean_simple():
    raw_bytes = fixture_path("clean_simple.eml").read_bytes()
    parsed = EmailParser.parse(raw_bytes)
    findings = run_all_detectors(parsed)

    # Clean email should not trigger any high or critical findings
    severe_findings = [f for f in findings if f.severity in [SeverityLevel.high, SeverityLevel.critical]]
    assert len(severe_findings) == 0


def test_detectors_bec_urgent():
    raw_bytes = fixture_path("bec_urgent.eml").read_bytes()
    parsed = EmailParser.parse(raw_bytes)
    findings = run_all_detectors(parsed)

    detector_names = [f.detector for f in findings]
    titles = [f.title for f in findings]

    assert "identity_spoofing" in detector_names
    assert "bec_intent" in detector_names

    # Check specific grounded findings
    assert any("Reply-To Domain Mismatch" in t for t in titles)
    assert any("Typosquatting" in t for t in titles)
    assert any("Business Email Compromise" in t for t in titles)

    # All these should have high severity
    for f in findings:
        if "Reply-To" in f.title or "Business Email Compromise" in f.title:
            assert f.severity == SeverityLevel.high
            assert f.confidence >= 0.85


def test_detectors_phishing_url():
    raw_bytes = fixture_path("phishing_url.eml").read_bytes()
    parsed = EmailParser.parse(raw_bytes)
    findings = run_all_detectors(parsed)

    titles = [f.title for f in findings]
    assert any("Direct IP-Based Hyperlink" in t for t in titles)
    assert any("Credential Harvesting" in t for t in titles)

    ip_finding = next(f for f in findings if "IP-Based" in f.title)
    assert ip_finding.severity == SeverityLevel.high
    assert "192.168.1.100" in str(ip_finding.raw_evidence)


def test_detectors_spf_fail():
    raw_bytes = fixture_path("spf_fail.eml").read_bytes()
    parsed = EmailParser.parse(raw_bytes)
    findings = run_all_detectors(parsed)

    titles = [f.title for f in findings]
    assert any("SPF Authentication Hard Fail" in t for t in titles)
    assert any("DMARC Policy Alignment Failure" in t for t in titles)

    spf_finding = next(f for f in findings if "SPF" in f.title)
    assert spf_finding.severity == SeverityLevel.high
    assert spf_finding.raw_evidence.get("provenance") == "unverified_header_claim"


def test_detectors_attachment_macro():
    raw_bytes = fixture_path("attachment_macro.eml").read_bytes()
    parsed = EmailParser.parse(raw_bytes)
    findings = run_all_detectors(parsed)

    titles = [f.title for f in findings]
    assert any("Macro-Enabled" in t for t in titles)

    macro_finding = next(f for f in findings if "Macro-Enabled" in f.title)
    assert macro_finding.severity == SeverityLevel.high
    assert macro_finding.raw_evidence.get("filename") == "invoice_2024.xlsm"


def test_detectors_double_extension_masking():
    raw_bytes = fixture_path("clean_simple.eml").read_bytes()
    parsed = EmailParser.parse(raw_bytes)

    # Inject double extension attachment into parsed object
    parsed.attachments.append(AttachmentData(
        filename="payroll_update.pdf.exe",
        content_type="application/octet-stream",
        size=1024,
        sha256="a" * 64,
        is_macro=False,
        is_inline=False,
        content_id=None,
    ))

    findings = SuspiciousAttachmentDetector().analyze(parsed)
    assert len(findings) == 1
    assert findings[0].severity == SeverityLevel.critical
    assert "Double Extension" in findings[0].title


def test_detectors_deceptive_anchor_url():
    raw_bytes = fixture_path("clean_simple.eml").read_bytes()
    parsed = EmailParser.parse(raw_bytes)

    # Inject deceptive link: displays paypal.com but goes to attacker-site.xyz
    parsed.urls.append({
        "url": "https://attacker-site.xyz/login",
        "defanged": "hxxps://attacker-site[.]xyz/login",
        "domain": "attacker-site.xyz",
        "is_ip": False,
        "source": "html_anchor",
        "anchor_text": "https://www.paypal.com/signin",
        "occurrences": 1,
    })

    findings = SuspiciousUrlDetector().analyze(parsed)
    assert any("Deceptive Link Text Mismatch" in f.title for f in findings)
    deceptive = next(f for f in findings if "Deceptive Link Text Mismatch" in f.title)
    assert deceptive.severity == SeverityLevel.high
    assert deceptive.raw_evidence["claimed_host"] == "paypal.com"
