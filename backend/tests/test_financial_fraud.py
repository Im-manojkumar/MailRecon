import pytest
from app.detectors.financial_fraud import FinancialFraudDetector


def test_validate_iban():
    # Valid German IBAN
    assert FinancialFraudDetector.validate_iban("DE89370400440532013000") is True
    # Valid British IBAN
    assert FinancialFraudDetector.validate_iban("GB82WEST12345698765432") is True
    # With spaces
    assert FinancialFraudDetector.validate_iban("GB82 WEST 1234 5698 7654 32") is True
    # Invalid checksum
    assert FinancialFraudDetector.validate_iban("GB82WEST12345698765433") is False
    # Too short
    assert FinancialFraudDetector.validate_iban("GB82") is False


def test_validate_aba_routing():
    # Valid ABA routing numbers
    assert FinancialFraudDetector.validate_aba_routing("021000021") is True  # Chase NY
    assert FinancialFraudDetector.validate_aba_routing("121000248") is True  # Wells Fargo CA
    assert FinancialFraudDetector.validate_aba_routing("111000025") is True  # FRB Dallas
    # Invalid checksum
    assert FinancialFraudDetector.validate_aba_routing("123456789") is False
    # Not 9 digits
    assert FinancialFraudDetector.validate_aba_routing("12345") is False


def test_payment_diversion_detection():
    subject = "URGENT: Updated Wire Instructions for Invoice INV-88921"
    body = """
    Good morning,
    Please be advised that our bank accounts have changed due to our annual audit.
    Kindly update your remittance records and wire the pending payment of $85,450.00
    to our new corporate account:
    Bank: Barclays UK
    IBAN: GB82WEST12345698765432
    Routing Transit: 021000021
    SWIFT: BARCGB22
    
    Please wire funds immediately today to avoid service disruption.
    """

    res = FinancialFraudDetector.analyze(
        subject=subject,
        body_text=body,
        from_header="accounting@acme-vendor.com",
    )

    assert res.is_financial_threat is True
    assert res.risk_level in ["high", "critical"]
    assert "GB82WEST12345698765432" in res.bank_accounts
    assert "021000021" in res.routing_numbers
    assert "BARCGB22" in res.swift_codes
    assert any("$85,450.00" in amt for amt in res.amounts_mentioned)
    assert len(res.diversion_indicators) >= 2
    assert any("Bank Account Change Claimed" in ind for ind in res.diversion_indicators)


def test_vendor_impersonation_mismatch():
    subject = "Overdue Microsoft 365 Cloud Subscription - Pending Invoice"
    body = """
    Your enterprise Microsoft 365 license payment of $4,200.00 is past due.
    Please remit payment immediately to our collections portal.
    Ref: INV-2026-9901
    """

    res = FinancialFraudDetector.analyze(
        subject=subject,
        body_text=body,
        from_header="billing@fake-msft-invoicing.net",
    )

    assert res.vendor_mismatch is not None
    assert "Microsoft" in res.vendor_mismatch
    assert "fake-msft-invoicing.net" in res.vendor_mismatch
    assert res.is_financial_threat is True


def test_cryptocurrency_detection():
    subject = "Confidential payment requested"
    body = "Transfer the ransom of 0.5 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or 0x71C7656EC7ab88b098defB751B7401B5f6d8976F."

    res = FinancialFraudDetector.analyze(subject=subject, body_text=body)
    assert len(res.crypto_wallets) == 2
    assert any(w["address"] == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" for w in res.crypto_wallets)
    assert any("0x71C7656EC7ab88b098defB751B7401B5f6d8976F" in w["address"] for w in res.crypto_wallets)


def test_clean_message_no_financial_threat():
    subject = "Sprint Planning Sync"
    body = "Hi team, let's meet tomorrow at 10 AM to discuss backlog items."

    res = FinancialFraudDetector.analyze(subject=subject, body_text=body)
    assert res.is_financial_threat is False
    assert res.risk_level == "none"
    assert len(res.bank_accounts) == 0
    assert len(res.routing_numbers) == 0
