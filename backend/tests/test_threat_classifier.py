import pytest
from app.scoring.threat_classifier import MultiClassThreatClassifier, ThreatCategory


def test_classify_credential_phishing():
    subject = "URGENT: Password Expired - Verify Your Microsoft 365 Account Immediately"
    body = "Your session has timed out. Click here to login and verify your credentials: http://fake-login.com"
    findings = [
        {"detector": "url_detector", "severity": "critical", "title": "Credential Phishing URL Detected"},
    ]
    obfuscation = {"has_evasion": True}

    res = MultiClassThreatClassifier.classify(
        subject=subject,
        body_text=body,
        from_header="security@m365-alert-notice.com",
        findings=findings,
        obfuscation=obfuscation,
        risk_score=0.85,
    )

    assert res.primary_category == ThreatCategory.CREDENTIAL_PHISHING.value
    assert res.confidence >= 0.70
    assert len(res.justification) > 0
    assert "Credential Phishing" in res.category_label


def test_classify_malware_delivery():
    subject = "Quarterly Invoice Attached"
    body = "Please review the attached spreadsheet for invoice details."
    findings = [
        {"detector": "macro_analyzer", "severity": "critical", "title": "Malicious Auto-Executing Macro Found"},
    ]
    macros = [
        {"filename": "invoice.xlsm", "risk_level": "critical", "has_macros": True},
    ]

    res = MultiClassThreatClassifier.classify(
        subject=subject,
        body_text=body,
        from_header="billing@supplier.com",
        findings=findings,
        macros=macros,
        risk_score=0.90,
    )

    assert res.primary_category == ThreatCategory.MALWARE_DELIVERY.value
    assert res.confidence >= 0.75
    assert any("VBA" in j or "macro" in j.lower() for j in res.justification)


def test_classify_ceo_impersonation():
    subject = "Quick Task - Need Confidential Wire"
    body = "Are you at your desk? I am currently in an executive meeting and cannot speak now. Please handle this urgent task immediately."
    from_header = "Chief Executive Officer <ceo.personal.inbox@gmail.com>"
    findings = [
        {"detector": "display_name", "severity": "high", "title": "Executive Display Name Spoofing Detected"},
    ]

    res = MultiClassThreatClassifier.classify(
        subject=subject,
        body_text=body,
        from_header=from_header,
        findings=findings,
        risk_score=0.80,
    )

    assert res.primary_category == ThreatCategory.CEO_IMPERSONATION.value
    assert "CEO Impersonation" in res.category_label


def test_classify_payment_diversion():
    subject = "Notice of Change: Updated Remittance Details"
    body = "Please update our payment details and wire all pending funds to IBAN GB82WEST12345698765432."
    financial_res = {
        "is_financial_threat": True,
        "threat_score": 0.85,
        "bank_accounts": ["GB82WEST12345698765432"],
        "diversion_indicators": ["Bank Account Change Claimed", "Valid International Bank Account Number (IBAN)"],
        "vendor_mismatch": None,
    }

    res = MultiClassThreatClassifier.classify(
        subject=subject,
        body_text=body,
        from_header="accounts@legit-vendor.com",
        findings=[],
        financial_result=financial_res,
        risk_score=0.85,
    )

    assert res.primary_category == ThreatCategory.PAYMENT_DIVERSION.value
    assert "Payment Diversion" in res.category_label
    assert any("bank account" in j.lower() or "financial" in j.lower() for j in res.justification)


def test_classify_spam_reconnaissance():
    subject = "Special Weekend Deals! 50% Off Everything"
    body = "Check out our catalog. If you wish to unsubscribe or opt-out, click here."

    res = MultiClassThreatClassifier.classify(
        subject=subject,
        body_text=body,
        from_header="newsletter@promotions.com",
        findings=[],
        risk_score=0.10,
    )

    assert res.primary_category == ThreatCategory.SPAM_RECONNAISSANCE.value


def test_classify_legitimate():
    subject = "Engineering Weekly Status Report"
    body = "Hi team, attached is the status report for sprint 42. All milestones achieved."
    dns_validation = {
        "alignment": {"dmarc_pass": True},
        "spf": {"is_ip_authorized": True},
    }
    domain_intel = {
        "domain_age_days": 1500,
        "is_newly_registered": False,
    }

    res = MultiClassThreatClassifier.classify(
        subject=subject,
        body_text=body,
        from_header="lead@company.com",
        findings=[],
        dns_validation=dns_validation,
        domain_intel=domain_intel,
        risk_score=0.05,
    )

    assert res.primary_category == ThreatCategory.LEGITIMATE.value
    assert "Legitimate" in res.category_label
    assert res.confidence >= 0.80
