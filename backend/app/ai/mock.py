"""
Mock AI Provider for MailRecon AI.
Provides deterministic, evidence-grounded forensic summaries for testing and offline development.
Zero network calls, zero hallucinated indicators.
"""
from typing import List

from app.ai.base import AIAnalysisResult, BaseAIProvider
from app.ai.grounding import validate_grounding
from app.detectors.base import FindingData
from app.models.finding import SeverityLevel
from app.parser.email_parser import ParsedEmailResult


class MockAIProvider(BaseAIProvider):
    name = "mock"

    async def generate_analysis(
        self, parsed: ParsedEmailResult, findings: List[FindingData]
    ) -> AIAnalysisResult:
        subject = parsed.headers.get("Subject", "(No Subject)")
        sender = parsed.headers.get("From", "(Unknown Sender)")

        # Categorize by active findings
        has_bec = any(f.detector == "bec_intent" for f in findings)
        has_spoof = any(f.detector == "identity_spoofing" for f in findings)
        has_auth_fail = any(f.detector == "auth_failure" for f in findings)
        has_url = any(f.detector == "suspicious_url" for f in findings)
        has_attachment = any(f.detector == "suspicious_attachment" for f in findings)
        has_neural = any(f.detector == "neural_1dcnn_bigru" for f in findings)

        tactics: List[str] = []
        actions: List[str] = []
        citations: List[str] = []

        # 1. Clean / Benign case
        if not findings or all(f.severity in [SeverityLevel.info, SeverityLevel.low] for f in findings):
            attack_vector = "Benign Corporate Communication"
            summary = (
                f"Forensic analysis of email '{subject}' from {sender} revealed no active threat indicators. "
                "Email authentication parameters appear consistent, no deceptive hyperlinks or malicious attachments "
                "were identified, and textual sequence modeling reflects standard routine correspondence."
            )
            tactics.append("Legitimate routine correspondence")
            actions.extend([
                "No containment action required.",
                "Deliver to recipient mailbox normally.",
            ])
            citations.extend(["headers.From", "headers.Subject"])
            if "Authentication-Results" in parsed.headers:
                citations.append("headers.Authentication-Results")

        # 2. BEC / Impersonation case
        elif has_bec or (has_spoof and "wire" in subject.lower()):
            attack_vector = "Business Email Compromise (BEC) / Wire Fraud"
            summary = (
                f"High-priority threat detected: Email '{subject}' exhibits classic Business Email Compromise patterns. "
                f"The message attempts executive authority impersonation to coerce the recipient into executing "
                "an urgent financial wire transfer while enforcing secrecy and discouraging out-of-band verification. "
            )
            if has_spoof:
                tactics.append("Executive display name impersonation and sender address spoofing")
            if has_bec:
                tactics.append("Urgent wire transfer demand with confidentiality pressure")
            if has_neural:
                tactics.append("Deep learning sequence model detected deceptive coercion patterns")
                summary += "Neural linguistic sequence analysis confirmed structural attack characteristics."

            actions.extend([
                "DO NOT process any financial transactions, wire transfers, or gift card requests.",
                "Verify the request directly with the purported executive via known voice telephone channel.",
                "Block sender address and lookalike domain at the email security perimeter.",
                "Search corporate mail logs for identical subject lines targeting other employees.",
            ])
            for f in findings:
                if f.detector in ["bec_intent", "identity_spoofing", "neural_1dcnn_bigru"]:
                    citations.append(f"{f.detector}: {f.evidence_ref}")

        # 3. Credential Phishing / Suspicious URL
        elif has_url or (has_neural and any("login" in u.get("url", "").lower() for u in parsed.urls)):
            attack_vector = "Credential Harvesting Phishing"
            summary = (
                f"Targeted credential phishing attack detected in email '{subject}'. "
                "The email body contains deceptive hyperlinks designed to mislead recipients into visiting unverified "
                "or spoofed authentication portals to harvest credentials."
            )
            tactics.append("Deceptive hyperlink masking and credential harvesting lures")
            if has_auth_fail:
                tactics.append("Email domain authentication failure (SPF/DKIM/DMARC misalignment)")
            if has_neural:
                tactics.append("Neural classifier identified linguistic credential lure markers")

            actions.extend([
                "Block observed target URLs and landing page domains at the web proxy and mail gateway.",
                "If recipient accessed the link, initiate password reset and terminate active Okta/M365 sessions.",
                "Submit malicious URLs to corporate threat intelligence feed.",
            ])
            for f in findings:
                if f.detector in ["suspicious_url", "auth_failure", "neural_1dcnn_bigru"]:
                    citations.append(f"{f.detector}: {f.evidence_ref}")

        # 4. Malicious Attachment
        elif has_attachment:
            attack_vector = "Malicious Attachment Delivery"
            summary = (
                f"Malware delivery attempt detected in email '{subject}'. "
                "The message contains weaponized attachments (such as macro-enabled spreadsheets, executable binaries, "
                "or obfuscated scripts) configured to trigger malicious execution upon opening."
            )
            tactics.append("Weaponized document / executable attachment delivery")
            if has_neural:
                tactics.append("Linguistic framing to induce attachment opening")

            actions.extend([
                "Quarantine the malicious attachment and delete the message from the recipient's inbox.",
                "Initiate an EDR endpoint scan on recipient workstation to detect unauthorized process execution.",
                "Add attachment SHA-256 hashes to corporate endpoint blocklist.",
            ])
            for f in findings:
                if f.detector in ["suspicious_attachment", "neural_1dcnn_bigru"]:
                    citations.append(f"{f.detector}: {f.evidence_ref}")

        # 5. General Suspicious Email / Auth Failure
        else:
            attack_vector = "Suspicious Email / Domain Misalignment"
            summary = (
                f"Anomalous email detected: '{subject}'. "
                "The message presents authentication anomalies or suspicious sender patterns that violate security policies."
            )
            tactics.append("Authentication misalignment / policy anomaly")
            actions.extend([
                "Review mail transport rules for sender domain.",
                "Verify whether sender is an authorized external contractor or partner.",
            ])
            citations.extend([f"{f.detector}: {f.evidence_ref}" for f in findings])

        result = AIAnalysisResult(
            executive_summary=summary.strip(),
            attack_vector=attack_vector,
            threat_actor_tactics=tactics,
            recommended_actions=actions,
            evidence_citations=citations,
            is_grounded=True,
            provider="mock",
        )

        return validate_grounding(result, parsed, findings)
