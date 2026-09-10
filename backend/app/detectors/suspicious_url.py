import re
from typing import List
from urllib.parse import urlparse

from app.detectors.base import BaseDetector, FindingData
from app.models.finding import SeverityLevel
from app.parser.email_parser import ParsedEmailResult

CREDENTIAL_LURE_KEYWORDS = [
    "login", "verify", "account", "signin", "sign-in",
    "password", "credential", "security-update", "secure",
    "billing", "confirm", "wallet", "banking", "auth", "portal"
]

HIGH_ABUSE_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".buzz", ".work", ".icu", ".sbs", ".rest", ".click", ".monster"
}

REPUTABLE_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "github.com", "paypal.com", "linkedin.com", "adobe.com"
}


class SuspiciousUrlDetector(BaseDetector):
    name = "suspicious_url"

    def analyze(self, parsed: ParsedEmailResult) -> List[FindingData]:
        findings: List[FindingData] = []
        urls = parsed.urls

        for idx, u in enumerate(urls):
            domain = u["domain"]
            url_str = u["url"]
            defanged = u["defanged"]
            is_ip = u["is_ip"]
            anchor = u.get("anchor_text") or ""
            ev_ref = f"urls[{idx}].{domain}"

            # 1. IP-Based URL
            if is_ip:
                findings.append(FindingData(
                    detector=self.name,
                    severity=SeverityLevel.high,
                    title=f"Direct IP-Based Hyperlink ({defanged})",
                    detail=(
                        f"The email embeds a URL referencing a direct IP address ('{domain}') rather than a registered domain. "
                        "Legitimate enterprise services rarely link directly to IP endpoints, often signaling compromised hosts."
                    ),
                    evidence_ref=ev_ref,
                    confidence=0.95,
                    raw_evidence={
                        "url": url_str,
                        "defanged": defanged,
                        "ip_host": domain,
                        "source": u.get("source"),
                    }
                ))

            # 2. Deceptive Anchor Text Mismatch
            if anchor and ("." in anchor or anchor.lower().startswith(("http", "www."))):
                # Clean anchor to extract apparent domain
                clean_anchor = anchor.lower().replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
                if "." in clean_anchor and clean_anchor != domain and not domain.endswith(f".{clean_anchor}"):
                    findings.append(FindingData(
                        detector=self.name,
                        severity=SeverityLevel.high,
                        title=f"Deceptive Link Text Mismatch (Claims '{clean_anchor}' -> routes to '{domain}')",
                        detail=(
                            f"The visible link text displays '{anchor}' to deceive users, but the actual target "
                            f"routes to a different host '{domain}'. This is a hallmark credential harvesting technique."
                        ),
                        evidence_ref=ev_ref,
                        confidence=0.95,
                        raw_evidence={
                            "anchor_text": anchor,
                            "claimed_host": clean_anchor,
                            "actual_domain": domain,
                            "actual_url_defanged": defanged,
                        }
                    ))

            # 3. Credential Harvesting Subdomain / Path Pattern
            has_lure_keyword = any(k in domain.lower() for k in CREDENTIAL_LURE_KEYWORDS)
            tld = "." + domain.split(".")[-1].lower() if "." in domain else ""
            is_abuse_tld = tld in HIGH_ABUSE_TLDS

            if (has_lure_keyword or is_abuse_tld) and not any(domain.endswith(f".{rep}") or domain == rep for rep in REPUTABLE_DOMAINS):
                severity = SeverityLevel.high if (has_lure_keyword and is_abuse_tld) else SeverityLevel.medium
                matched_keywords = [k for k in CREDENTIAL_LURE_KEYWORDS if k in domain.lower()]
                findings.append(FindingData(
                    detector=self.name,
                    severity=severity,
                    title=f"Suspicious Credential Harvesting URL Pattern ({defanged})",
                    detail=(
                        f"The URL domain '{domain}' incorporates credential lure keywords ({matched_keywords}) "
                        f"{'and a high-abuse TLD (' + tld + ')' if is_abuse_tld else ''}. "
                        "This structure is characteristic of impersonated login portals."
                    ),
                    evidence_ref=ev_ref,
                    confidence=0.88,
                    raw_evidence={
                        "domain": domain,
                        "defanged": defanged,
                        "matched_keywords": matched_keywords,
                        "tld": tld,
                        "is_abuse_tld": is_abuse_tld,
                    }
                ))

        return findings
