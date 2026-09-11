"""
Payment Diversion and Invoice Fraud Detector for MailRecon AI.
Extracts banking identifiers (IBAN, ABA Routing, SWIFT/BIC, Crypto wallets),
detects fraudulent payment redirection phrasing, vendor identity mismatches,
and scores BEC financial risk.
"""
from dataclasses import asdict, dataclass
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("mailrecon.detectors.financial_fraud")


@dataclass
class FinancialForensicsResult:
    is_financial_threat: bool
    risk_level: str  # "critical", "high", "medium", "low", "none"
    bank_accounts: List[str]
    routing_numbers: List[str]
    swift_codes: List[str]
    crypto_wallets: List[Dict[str, str]]
    amounts_mentioned: List[str]
    invoice_numbers: List[str]
    diversion_indicators: List[str]
    vendor_mismatch: Optional[str]
    threat_score: float  # 0.0 to 1.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FinancialFraudDetector:
    """
    Forensic engine analyzing messages for financial fraud, payment diversion,
    wire account changes, and fraudulent invoice interception.
    """

    # 1. Banking Regex Patterns
    # IBAN format: 2 letters, 2 digits, up to 30 alphanumeric
    IBAN_REGEX = re.compile(r"\b([A-Z]{2}[0-9]{2}[A-Z0-9]{11,30})\b")

    # US ABA 9-digit routing numbers
    ABA_ROUTING_REGEX = re.compile(r"\b([0-9]{9})\b")

    # SWIFT / BIC: 8 or 11 characters
    SWIFT_REGEX = re.compile(r"\b([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b")

    # Cryptocurrency Wallets
    BTC_LEGACY_REGEX = re.compile(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
    BTC_BECH32_REGEX = re.compile(r"\b(bc1[a-z0-9]{39,59})\b")
    ETH_REGEX = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")

    # Currency Amounts
    AMOUNT_REGEX = re.compile(
        r"(?:[\$\€\£\¥]|USD|EUR|GBP|CAD|AUD)\s?[0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{2})?"
        r"|[0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{2})?\s?(?:USD|EUR|GBP|dollars|euros)",
        re.IGNORECASE,
    )

    # Invoice Identifiers
    INVOICE_NUM_REGEX = re.compile(
        r"\b(?:INV(?:OICE)?|BILL|REF|ORDER)[\s\-\#\:\_]{1,3}([A-Z0-9\-]{4,15})\b",
        re.IGNORECASE,
    )

    # High-Risk Payment Diversion Phrases
    DIVERSION_PHRASES = [
        ("bank account.*(?:changed|updated|modified|new)", "Bank Account Change Claimed"),
        ("new.*(?:banking|bank|account|wire).*details", "New Banking Details Provided"),
        ("update.*(?:our|my|remittance|vendor).*records", "Request to Update Vendor Payment Records"),
        ("(?:wire|transfer).*(?:funds|payment|balance).*immediately", "Urgent Wire Transfer Requested"),
        ("wire instructions attached", "Wire Transfer Instructions Attached"),
        ("payment diversion|divert payment", "Direct Payment Diversion Reference"),
        ("due to (?:an )?audit.*(?:hold|delay|change)", "Audit-Induced Payment Redirection"),
        ("confidential.*(?:transaction|acquisition|disbursement)", "Executive Confidential Wire Request"),
        ("electronic funds transfer.*(?:new|updated|revised)", "Revised Electronic Funds Transfer"),
        ("pending invoice.*pay to", "Pending Invoice Payment Request"),
        ("remittance advice.*new account", "Remittance Advice Redirected"),
    ]

    # Recognized Enterprise Vendor Brands (for vendor discrepancy detection)
    KNOWN_VENDOR_BRANDS = {
        "microsoft": "microsoft.com",
        "google": "google.com",
        "apple": "apple.com",
        "amazon": "amazon.com",
        "adobe": "adobe.com",
        "salesforce": "salesforce.com",
        "oracle": "oracle.com",
        "dell": "dell.com",
        "hp": "hp.com",
        "cisco": "cisco.com",
        "zoom": "zoom.us",
        "slack": "slack.com",
        "docusign": "docusign.com",
        "fedex": "fedex.com",
        "dhl": "dhl.com",
        "quickbooks": "intuit.com",
        "intuit": "intuit.com",
    }

    @staticmethod
    def validate_iban(iban: str) -> bool:
        """Validates IBAN checksum using standard ISO 7064 mod-97 check."""
        clean = re.sub(r"[\s\-]", "", iban).upper()
        if len(clean) < 15 or len(clean) > 34:
            return False
        # Move first 4 characters to the end
        rearranged = clean[4:] + clean[:4]
        # Replace letters with digits (A=10, B=11, ... Z=35)
        numeric_str = ""
        for char in rearranged:
            if char.isdigit():
                numeric_str += char
            elif char.isalpha():
                numeric_str += str(ord(char) - ord("A") + 10)
            else:
                return False
        try:
            return int(numeric_str) % 97 == 1
        except Exception:
            return False

    @staticmethod
    def validate_aba_routing(routing: str) -> bool:
        """Validates 9-digit US ABA routing transit number using official Federal Reserve checksum."""
        digits = re.sub(r"\D", "", routing)
        if len(digits) != 9:
            return False
        d = [int(c) for c in digits]
        checksum = (
            3 * (d[0] + d[3] + d[6])
            + 7 * (d[1] + d[4] + d[7])
            + 1 * (d[2] + d[5] + d[8])
        ) % 10
        return checksum == 0

    @classmethod
    def analyze(
        cls,
        subject: str,
        body_text: str,
        from_header: Optional[str] = None,
        reply_to: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
    ) -> FinancialForensicsResult:
        """
        Analyzes message text and headers for financial scam patterns.
        """
        combined_text = f"{subject or ''}\n{body_text or ''}"
        diversion_indicators: List[str] = []
        threat_points = 0.0

        # 1. Detect Payment Diversion Phrasing
        for pattern, label in cls.DIVERSION_PHRASES:
            if re.search(pattern, combined_text, re.IGNORECASE):
                diversion_indicators.append(label)
                threat_points += 0.25

        # 2. Extract and Validate IBANs
        found_ibans: List[str] = []
        raw_ibans = cls.IBAN_REGEX.findall(combined_text.upper())
        for raw_iban in raw_ibans:
            if cls.validate_iban(raw_iban):
                found_ibans.append(raw_iban)
                threat_points += 0.35
                diversion_indicators.append(f"Valid International Bank Account Number (IBAN): {raw_iban[:4]}****{raw_iban[-4:]}")

        # 3. Extract and Validate ABA Routing Numbers
        found_routings: List[str] = []
        raw_routings = cls.ABA_ROUTING_REGEX.findall(combined_text)
        for raw_aba in raw_routings:
            # Check context: words like routing, aba, bank, transit nearby
            aba_idx = combined_text.find(raw_aba)
            start_window = max(0, aba_idx - 40)
            end_window = min(len(combined_text), aba_idx + len(raw_aba) + 40)
            context = combined_text[start_window:end_window].lower()
            if any(k in context for k in ["routing", "aba", "transit", "bank", "wire"]):
                if cls.validate_aba_routing(raw_aba):
                    found_routings.append(raw_aba)
                    threat_points += 0.30
                    diversion_indicators.append(f"Valid ABA Routing Transit Number: {raw_aba}")

        # 4. Extract SWIFT / BIC codes
        found_swifts: List[str] = []
        raw_swifts = cls.SWIFT_REGEX.findall(combined_text.upper())
        for raw_swift in raw_swifts:
            # Exclude false positives that are common English words
            if raw_swift in ["CONFIDENTIAL", "NOTIFICATION", "REGISTRATION", "VERIFICATION"]:
                continue
            idx = combined_text.upper().find(raw_swift)
            start = max(0, idx - 40)
            end = min(len(combined_text), idx + len(raw_swift) + 40)
            context = combined_text[start:end].lower()
            if any(k in context for k in ["swift", "bic", "wire", "bank", "transfer", "code"]):
                found_swifts.append(raw_swift)
                threat_points += 0.20

        # 5. Extract Cryptocurrency Addresses
        found_crypto: List[Dict[str, str]] = []
        for btc in cls.BTC_LEGACY_REGEX.findall(combined_text):
            found_crypto.append({"type": "Bitcoin (Legacy)", "address": btc})
            threat_points += 0.35
        for btc in cls.BTC_BECH32_REGEX.findall(combined_text):
            found_crypto.append({"type": "Bitcoin (SegWit)", "address": btc})
            threat_points += 0.35
        for eth in cls.ETH_REGEX.findall(combined_text):
            found_crypto.append({"type": "Ethereum", "address": eth})
            threat_points += 0.35

        # 6. Extract Mentioned Amounts
        amounts = list(set(cls.AMOUNT_REGEX.findall(combined_text)))[:5]

        # 7. Extract Invoice / Billing References
        invoices = list(set(cls.INVOICE_NUM_REGEX.findall(combined_text)))[:5]

        # 8. Check for Invoice Attachments
        has_invoice_attachment = False
        if attachments:
            for att in attachments:
                fn = (att.get("filename") or "").lower()
                if any(k in fn for k in ["invoice", "bill", "remittance", "payment", "wire", "receipt"]):
                    has_invoice_attachment = True
                    threat_points += 0.15
                    diversion_indicators.append(f"Financial Attachment Detected: {fn}")
                    break

        # 9. Vendor Impersonation / Domain Mismatch Check
        vendor_mismatch: Optional[str] = None
        from_domain = ""
        if from_header:
            m = re.search(r"@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", from_header)
            if m:
                from_domain = m.group(1).lower()

        lower_body = combined_text.lower()
        for brand, legitimate_domain in cls.KNOWN_VENDOR_BRANDS.items():
            if re.search(r"\b" + brand + r"\b", lower_body):
                if from_domain and not from_domain.endswith(legitimate_domain):
                    # Check if email is claiming to be an invoice or payment for this brand
                    if any(k in lower_body for k in ["invoice", "payment", "billing", "receipt", "account"]):
                        vendor_mismatch = (
                            f"Email references '{brand.capitalize()}' invoices/billing, but was sent from "
                            f"unrelated domain '{from_domain}' (Legitimate domain is '{legitimate_domain}')."
                        )
                        diversion_indicators.append(f"Vendor Mismatch: {brand.capitalize()} impersonation")
                        threat_points += 0.40
                        break

        # Calculate final threat score and risk level
        threat_score = min(1.0, round(threat_points, 2))
        is_threat = (
            len(found_ibans) > 0
            or len(found_routings) > 0
            or len(found_crypto) > 0
            or len(diversion_indicators) >= 2
            or vendor_mismatch is not None
        )

        if threat_score >= 0.70:
            risk_level = "critical"
        elif threat_score >= 0.45:
            risk_level = "high"
        elif threat_score >= 0.20:
            risk_level = "medium"
        elif threat_score > 0.0:
            risk_level = "low"
        else:
            risk_level = "none"

        return FinancialForensicsResult(
            is_financial_threat=is_threat,
            risk_level=risk_level,
            bank_accounts=found_ibans,
            routing_numbers=found_routings,
            swift_codes=found_swifts,
            crypto_wallets=found_crypto,
            amounts_mentioned=amounts,
            invoice_numbers=invoices,
            diversion_indicators=diversion_indicators,
            vendor_mismatch=vendor_mismatch,
            threat_score=threat_score,
        )
