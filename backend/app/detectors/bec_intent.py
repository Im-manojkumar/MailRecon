import re
from typing import List

from app.detectors.base import BaseDetector, FindingData
from app.models.finding import SeverityLevel
from app.parser.email_parser import ParsedEmailResult

FINANCIAL_PATTERNS = [
    r"\bwire\s+transfer\b", r"\bbank\s+transfer\b", r"\bdirect\s+deposit\b",
    r"\bgift\s+card\b", r"\brouting\s+number\b", r"\bpayment\b",
    r"\binvoice\b", r"\bremittance\b", r"\bfunds?\s+transfer\b",
    r"\bpayroll\b", r"\bacquisition\b"
]

URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediate(?:ly)?\b", r"\basap\b",
    r"\bact\s+now\b", r"\btime\s+sensitive\b", r"\bright\s+away\b",
    r"\bprompt\s+attention\b", r"\btoday\b", r"\bquick(?:ly)?\b"
]

SECRECY_PATTERNS = [
    r"\bconfidential\b", r"\bstrictly\s+confidential\b",
    r"\bdo\s+not\s+discuss\b", r"\bkeep\s+this\s+between\s+us\b",
    r"\bprivate\s+request\b", r"\boffline\b", r"\bsecret\b"
]


class BecIntentDetector(BaseDetector):
    name = "bec_intent"

    def analyze(self, parsed: ParsedEmailResult) -> List[FindingData]:
        findings: List[FindingData] = []
        subject = parsed.headers.get("subject", "")
        body = parsed.body_text or ""
        full_text = f"{subject}\n{body}".lower()

        matched_financial = [p for p in FINANCIAL_PATTERNS if re.search(p, full_text)]
        matched_urgency = [p for p in URGENCY_PATTERNS if re.search(p, full_text)]
        matched_secrecy = [p for p in SECRECY_PATTERNS if re.search(p, full_text)]

        if matched_financial and matched_urgency:
            if matched_secrecy:
                findings.append(FindingData(
                    detector=self.name,
                    severity=SeverityLevel.high,
                    title="Business Email Compromise (BEC): Urgent Financial Secrecy Pattern",
                    detail=(
                        "The communication combines high-urgency language with financial transaction requests "
                        "and demands for confidentiality. This triad represents the classic signature of CEO fraud "
                        "and targeted business email compromise."
                    ),
                    evidence_ref="body.text",
                    confidence=0.92,
                    raw_evidence={
                        "financial_indicators": [p.replace(r"\b", "") for p in matched_financial],
                        "urgency_indicators": [p.replace(r"\b", "") for p in matched_urgency],
                        "secrecy_indicators": [p.replace(r"\b", "") for p in matched_secrecy],
                        "sample_subject": subject,
                    }
                ))
            else:
                findings.append(FindingData(
                    detector=self.name,
                    severity=SeverityLevel.medium,
                    title="Urgent Financial / Wire Transaction Request",
                    detail=(
                        "The email contains urgent payment or financial transfer language. "
                        "All banking or payment instruction changes must be verified through an out-of-band channel."
                    ),
                    evidence_ref="body.text",
                    confidence=0.82,
                    raw_evidence={
                        "financial_indicators": [p.replace(r"\b", "") for p in matched_financial],
                        "urgency_indicators": [p.replace(r"\b", "") for p in matched_urgency],
                        "sample_subject": subject,
                    }
                ))

        return findings
