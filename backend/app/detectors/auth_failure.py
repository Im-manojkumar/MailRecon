from typing import List

from app.detectors.base import BaseDetector, FindingData
from app.models.finding import SeverityLevel
from app.parser.email_parser import ParsedEmailResult


class AuthFailureDetector(BaseDetector):
    name = "auth_failure"

    def analyze(self, parsed: ParsedEmailResult) -> List[FindingData]:
        findings: List[FindingData] = []
        auth = parsed.auth_results or {}

        spf = auth.get("spf", {})
        dkim = auth.get("dkim", {})
        dmarc = auth.get("dmarc", {})

        # 1. SPF Failure
        spf_res = (spf.get("result") or "").lower()
        if spf_res == "fail":
            findings.append(FindingData(
                detector=self.name,
                severity=SeverityLevel.high,
                title="SPF Authentication Hard Fail",
                detail=(
                    f"The SPF check for '{spf.get('mailfrom') or 'sender'}' resulted in a hard failure (fail). "
                    "The sending relay IP is explicitly unauthorized according to the published SPF record."
                ),
                evidence_ref="headers.Authentication-Results.spf",
                confidence=0.95,
                raw_evidence={
                    "spf_result": spf_res,
                    "details": spf.get("details"),
                    "mailfrom": spf.get("mailfrom"),
                    "provenance": auth.get("provenance", "unverified_header_claim"),
                }
            ))
        elif spf_res == "softfail":
            findings.append(FindingData(
                detector=self.name,
                severity=SeverityLevel.medium,
                title="SPF Authentication Softfail",
                detail=(
                    f"The SPF check for '{spf.get('mailfrom') or 'sender'}' resulted in a soft failure (~all). "
                    "The transmitting IP is not listed as a designated sender."
                ),
                evidence_ref="headers.Authentication-Results.spf",
                confidence=0.85,
                raw_evidence={
                    "spf_result": spf_res,
                    "details": spf.get("details"),
                    "provenance": auth.get("provenance", "unverified_header_claim"),
                }
            ))
        elif spf_res in ["permerror", "temperror"]:
            findings.append(FindingData(
                detector=self.name,
                severity=SeverityLevel.low,
                title=f"SPF Evaluation Error ({spf_res.upper()})",
                detail=f"An error occurred while evaluating SPF: {spf.get('details')}",
                evidence_ref="headers.Authentication-Results.spf",
                confidence=0.70,
                raw_evidence={
                    "spf_result": spf_res,
                    "details": spf.get("details"),
                    "provenance": auth.get("provenance", "unverified_header_claim"),
                }
            ))

        # 2. DKIM Failure
        dkim_res = (dkim.get("result") or "").lower()
        if dkim_res == "fail":
            findings.append(FindingData(
                detector=self.name,
                severity=SeverityLevel.high,
                title="DKIM Cryptographic Signature Verification Failed",
                detail=(
                    f"The DKIM cryptographic signature for domain '{dkim.get('domain') or 'unknown'}' "
                    "failed validation. The email body or critical headers may have been modified in transit."
                ),
                evidence_ref="headers.Authentication-Results.dkim",
                confidence=0.95,
                raw_evidence={
                    "dkim_result": dkim_res,
                    "domain": dkim.get("domain"),
                    "selector": dkim.get("selector"),
                    "provenance": auth.get("provenance", "unverified_header_claim"),
                }
            ))

        # 3. DMARC Failure
        dmarc_res = (dmarc.get("result") or "").lower()
        if dmarc_res == "fail":
            findings.append(FindingData(
                detector=self.name,
                severity=SeverityLevel.high,
                title="DMARC Policy Alignment Failure",
                detail=(
                    f"The message failed DMARC policy validation for domain '{dmarc.get('from_domain') or 'sender'}'. "
                    "Neither SPF nor DKIM passed with appropriate identifier alignment."
                ),
                evidence_ref="headers.Authentication-Results.dmarc",
                confidence=0.95,
                raw_evidence={
                    "dmarc_result": dmarc_res,
                    "from_domain": dmarc.get("from_domain"),
                    "provenance": auth.get("provenance", "unverified_header_claim"),
                }
            ))

        return findings
