from email.utils import parseaddr
import re
from typing import List, Optional
from urllib.parse import urlparse

from app.detectors.base import BaseDetector, FindingData
from app.models.finding import SeverityLevel
from app.parser.email_parser import ParsedEmailResult

SUSPICIOUS_LEET_SUBS = [
    (r"1", "l"),
    (r"0", "o"),
    (r"3", "e"),
    (r"5", "s"),
    (r"vv", "w"),
    (r"rn", "m"),
]

VIP_KEYWORDS = [
    "ceo", "cfo", "coo", "cto", "president", "director",
    "executive", "payroll", "human resources", "admin",
    "helpdesk", "it support", "security team"
]


def extract_domain(email_str: str) -> Optional[str]:
    """Extract lowercase domain from an email string."""
    if not email_str:
        return None
    _, addr = parseaddr(email_str)
    if "@" in addr:
        return addr.split("@")[-1].lower().strip()
    return None


class IdentitySpoofingDetector(BaseDetector):
    name = "identity_spoofing"

    def analyze(self, parsed: ParsedEmailResult) -> List[FindingData]:
        findings: List[FindingData] = []
        headers = parsed.headers

        from_raw = headers.get("from", "")
        reply_to_raw = headers.get("reply_to", "")
        return_path_raw = headers.get("return_path", "")

        from_display, from_addr = parseaddr(from_raw)
        from_domain = extract_domain(from_raw)

        # 1. Reply-To Domain Mismatch (Classic BEC / Phishing vector)
        if reply_to_raw and from_domain:
            _, reply_to_addr = parseaddr(reply_to_raw)
            reply_to_domain = extract_domain(reply_to_raw)

            if reply_to_domain and reply_to_domain != from_domain:
                findings.append(FindingData(
                    detector=self.name,
                    severity=SeverityLevel.high,
                    title="Reply-To Domain Mismatch",
                    detail=(
                        f"The Reply-To address ('{reply_to_addr}') routes to a different domain "
                        f"('{reply_to_domain}') than the apparent sender ('{from_domain}'). "
                        "This technique is frequently used to divert victim replies away from legitimate senders."
                    ),
                    evidence_ref="headers.reply_to",
                    confidence=0.92,
                    raw_evidence={
                        "from": from_raw,
                        "reply_to": reply_to_raw,
                        "from_domain": from_domain,
                        "reply_to_domain": reply_to_domain,
                    }
                ))

        # 2. Typosquatting / Lookalike Domain Detection
        if from_domain:
            domain_name = from_domain.split(".")[0]
            # Check for leetspeak digit substitution inside alphabetical domain
            has_digit_sub = bool(re.search(r"[a-z]+[0-9]+[a-z]+", domain_name, re.IGNORECASE))
            if has_digit_sub:
                findings.append(FindingData(
                    detector=self.name,
                    severity=SeverityLevel.high,
                    title="Potential Domain Typosquatting Detected",
                    detail=(
                        f"The sender domain '{from_domain}' contains suspicious alphanumeric substitutions "
                        "resembling a lookalike or typosquatted brand domain."
                    ),
                    evidence_ref="headers.from",
                    confidence=0.88,
                    raw_evidence={
                        "from_domain": from_domain,
                        "domain_label": domain_name,
                    }
                ))

        # 3. Display Name Impersonation
        if from_display:
            display_lower = from_display.lower()
            # Check if display name claims an email address differing from actual sender
            display_email_m = re.search(r"[\w.-]+@[\w.-]+\.\w+", from_display)
            if display_email_m:
                claimed_email = display_email_m.group(0).lower()
                if from_addr.lower() != claimed_email:
                    findings.append(FindingData(
                        detector=self.name,
                        severity=SeverityLevel.high,
                        title="Display Name Email Spoofing",
                        detail=(
                            f"The display name '{from_display}' contains an email address '{claimed_email}' "
                            f"that does not match the actual envelope sender '{from_addr}'."
                        ),
                        evidence_ref="headers.from",
                        confidence=0.95,
                        raw_evidence={
                            "display_name": from_display,
                            "actual_address": from_addr,
                            "claimed_address": claimed_email,
                        }
                    ))
            elif any(vip in display_lower for vip in VIP_KEYWORDS):
                # Display name claims VIP role
                findings.append(FindingData(
                    detector=self.name,
                    severity=SeverityLevel.medium,
                    title="Executive / VIP Role Impersonation in Display Name",
                    detail=(
                        f"The sender display name '{from_display}' claims an executive or administrative authority title. "
                        "Verify whether the sender domain corresponds to authorized organizational mail."
                    ),
                    evidence_ref="headers.from",
                    confidence=0.75,
                    raw_evidence={
                        "display_name": from_display,
                        "from_address": from_addr,
                    }
                ))

        # 4. Return-Path Mismatch
        if return_path_raw and from_domain:
            return_path_domain = extract_domain(return_path_raw)
            if return_path_domain and return_path_domain != from_domain:
                findings.append(FindingData(
                    detector=self.name,
                    severity=SeverityLevel.low,
                    title="Envelope Return-Path Differs from Header From",
                    detail=(
                        f"The envelope bounce address ('{return_path_domain}') differs from the header From "
                        f"domain ('{from_domain}'). While common in automated mailing services, it warrants review."
                    ),
                    evidence_ref="headers.return_path",
                    confidence=0.65,
                    raw_evidence={
                        "from_domain": from_domain,
                        "return_path_domain": return_path_domain,
                    }
                ))

        return findings
