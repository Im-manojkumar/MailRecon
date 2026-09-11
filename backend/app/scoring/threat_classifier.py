"""
Multi-Class Threat Classification Engine for MailRecon AI.
Synthesizes header, body, URL, attachment, DNS, financial, and origin signals
to classify email threats into 5 distinct attack classes (plus Legitimate).
"""
from dataclasses import asdict, dataclass
import enum
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("mailrecon.scoring.threat_classifier")


class ThreatCategory(str, enum.Enum):
    CREDENTIAL_PHISHING = "CREDENTIAL_PHISHING"
    MALWARE_DELIVERY = "MALWARE_DELIVERY"
    CEO_IMPERSONATION = "CEO_IMPERSONATION"
    PAYMENT_DIVERSION = "PAYMENT_DIVERSION"
    SPAM_RECONNAISSANCE = "SPAM_RECONNAISSANCE"
    LEGITIMATE = "LEGITIMATE"


CATEGORY_LABELS = {
    ThreatCategory.CREDENTIAL_PHISHING: "Credential Phishing & Harvesting",
    ThreatCategory.MALWARE_DELIVERY: "Malware & Weaponized Payload Delivery",
    ThreatCategory.CEO_IMPERSONATION: "CEO Impersonation & Executive BEC",
    ThreatCategory.PAYMENT_DIVERSION: "Payment Diversion & Invoice Fraud",
    ThreatCategory.SPAM_RECONNAISSANCE: "Spam & Reconnaissance Probing",
    ThreatCategory.LEGITIMATE: "Legitimate Business Communication",
}

CATEGORY_ACTIONS = {
    ThreatCategory.CREDENTIAL_PHISHING: "Isolate recipient inbox, revoke session tokens, and block destination credential phishing domains on firewall/web gateway.",
    ThreatCategory.MALWARE_DELIVERY: "Quarantine attachment immediately, submit payload to sandbox analysis, and inspect endpoint EDR logs for execution indicators.",
    ThreatCategory.CEO_IMPERSONATION: "Alert executive assistant / security team, verify sender via secondary channel (phone/SMS), and enforce display-name spoofing rules.",
    ThreatCategory.PAYMENT_DIVERSION: "Freeze pending wire transfers, contact vendor accounting via verified out-of-band telephone, and verify banking coordinates directly.",
    ThreatCategory.SPAM_RECONNAISSANCE: "Update spam filter heuristics, block sender domain, and verify that recipient email was not harvested in a data breach.",
    ThreatCategory.LEGITIMATE: "No containment required. Routine email verified with clean protocol authentication.",
}


@dataclass
class ThreatClassificationResult:
    primary_category: str
    category_label: str
    confidence: float
    secondary_categories: List[Dict[str, Any]]
    justification: List[str]
    action_summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary_category": self.primary_category,
            "category_label": self.category_label,
            "confidence": self.confidence,
            "secondary_categories": self.secondary_categories,
            "justification": self.justification,
            "action_summary": self.action_summary,
        }


class MultiClassThreatClassifier:
    """
    Evaluates evidence across all forensic engines to assign an authoritative
    multi-class threat archetype.
    """

    @classmethod
    def classify(
        cls,
        subject: str,
        body_text: str,
        from_header: str,
        findings: List[Dict[str, Any]],
        financial_result: Optional[Dict[str, Any]] = None,
        macros: Optional[List[Dict[str, Any]]] = None,
        obfuscation: Optional[Dict[str, Any]] = None,
        dns_validation: Optional[Dict[str, Any]] = None,
        domain_intel: Optional[Dict[str, Any]] = None,
        risk_score: float = 0.0,
    ) -> ThreatClassificationResult:
        combined_text = f"{subject or ''}\n{body_text or ''}".lower()
        
        # Category accumulators (scores and justification reasons)
        cat_scores: Dict[ThreatCategory, float] = {
            ThreatCategory.CREDENTIAL_PHISHING: 0.0,
            ThreatCategory.MALWARE_DELIVERY: 0.0,
            ThreatCategory.CEO_IMPERSONATION: 0.0,
            ThreatCategory.PAYMENT_DIVERSION: 0.0,
            ThreatCategory.SPAM_RECONNAISSANCE: 0.0,
            ThreatCategory.LEGITIMATE: 0.0,
        }
        reasons: Dict[ThreatCategory, List[str]] = {cat: [] for cat in ThreatCategory}

        # 1. EVALUATE FINANCIAL FRAUD / PAYMENT DIVERSION SIGNALS
        if financial_result:
            if financial_result.get("is_financial_threat"):
                f_score = financial_result.get("threat_score", 0.5)
                cat_scores[ThreatCategory.PAYMENT_DIVERSION] += f_score * 1.5
                for ind in financial_result.get("diversion_indicators", []):
                    reasons[ThreatCategory.PAYMENT_DIVERSION].append(f"Financial indicator: {ind}")
            if financial_result.get("bank_accounts"):
                cat_scores[ThreatCategory.PAYMENT_DIVERSION] += 0.4
                reasons[ThreatCategory.PAYMENT_DIVERSION].append("Direct bank account / IBAN coordinates found in email body.")
            if financial_result.get("vendor_mismatch"):
                cat_scores[ThreatCategory.PAYMENT_DIVERSION] += 0.5
                reasons[ThreatCategory.PAYMENT_DIVERSION].append(financial_result["vendor_mismatch"])

        # 2. EVALUATE MALWARE DELIVERY SIGNALS
        if macros:
            high_risk_macros = [m for m in macros if m.get("risk_level") in ["high", "critical"]]
            if high_risk_macros:
                cat_scores[ThreatCategory.MALWARE_DELIVERY] += 0.9
                reasons[ThreatCategory.MALWARE_DELIVERY].append(f"Attachment contains weaponized VBA macros ({len(high_risk_macros)} suspicious functions detected).")
            elif len(macros) > 0:
                cat_scores[ThreatCategory.MALWARE_DELIVERY] += 0.4
                reasons[ThreatCategory.MALWARE_DELIVERY].append("Attachment contains VBA macro code.")

        for f in findings:
            title = (f.get("title") or "").lower()
            det = (f.get("detector") or "").lower()
            if "executable" in title or "malware" in title or "payload" in title or det == "macro_analyzer":
                cat_scores[ThreatCategory.MALWARE_DELIVERY] += 0.6
                reasons[ThreatCategory.MALWARE_DELIVERY].append(f"Finding: {f.get('title')}")

        # 3. EVALUATE CEO / EXECUTIVE IMPERSONATION SIGNALS
        executive_terms = ["ceo", "cfo", "chief executive", "president", "director", "executive", "urgent task", "are you at your desk"]
        has_exec_title = any(re.search(r"\b" + t + r"\b", (from_header or "").lower()) for t in executive_terms)
        has_urgency = any(re.search(r"\b" + u + r"\b", combined_text) for u in ["confidential", "in a meeting", "wire transfer immediately", "send me your phone", "cannot speak now", "handle this urgently"])

        if has_exec_title or any("display name" in (f.get("title") or "").lower() for f in findings):
            cat_scores[ThreatCategory.CEO_IMPERSONATION] += 0.6
            reasons[ThreatCategory.CEO_IMPERSONATION].append("Display name impersonates corporate executive leadership.")
            if has_urgency:
                cat_scores[ThreatCategory.CEO_IMPERSONATION] += 0.35
                reasons[ThreatCategory.CEO_IMPERSONATION].append("High-pressure executive urgency language detected.")

        for f in findings:
            title = (f.get("title") or "").lower()
            if "impersonation" in title or "spoof" in title or "vip" in title:
                cat_scores[ThreatCategory.CEO_IMPERSONATION] += 0.45
                reasons[ThreatCategory.CEO_IMPERSONATION].append(f"Finding: {f.get('title')}")

        # 4. EVALUATE CREDENTIAL PHISHING SIGNALS
        phish_keywords = ["login", "sign in", "password expired", "verify your account", "update account", "suspended", "unauthorized access", "click here to verify", "session timeout"]
        found_phish_words = [kw for kw in phish_keywords if kw in combined_text]
        if found_phish_words:
            cat_scores[ThreatCategory.CREDENTIAL_PHISHING] += min(0.5, len(found_phish_words) * 0.15)
            reasons[ThreatCategory.CREDENTIAL_PHISHING].append(f"Credential harvesting terminology detected ({', '.join(found_phish_words[:3])}).")

        for f in findings:
            title = (f.get("title") or "").lower()
            det = (f.get("detector") or "").lower()
            if "phishing" in title or "credential" in title or "qr code" in title or det in ["url_detector", "qr_detector"]:
                cat_scores[ThreatCategory.CREDENTIAL_PHISHING] += 0.5
                reasons[ThreatCategory.CREDENTIAL_PHISHING].append(f"Finding: {f.get('title')}")

        if obfuscation and obfuscation.get("has_evasion"):
            cat_scores[ThreatCategory.CREDENTIAL_PHISHING] += 0.3
            reasons[ThreatCategory.CREDENTIAL_PHISHING].append("Adversarial Unicode evasion detected designed to bypass spam filters.")

        # 5. EVALUATE SPAM / RECONNAISSANCE SIGNALS
        spam_keywords = ["unsubscribe", "opt-out", "newsletter", "marketing", "promotion", "special offer", "deal of the day"]
        found_spam_words = [kw for kw in spam_keywords if kw in combined_text]
        if found_spam_words and risk_score < 0.45:
            cat_scores[ThreatCategory.SPAM_RECONNAISSANCE] += 0.5
            reasons[ThreatCategory.SPAM_RECONNAISSANCE].append(f"Marketing / broadcast keywords identified: {', '.join(found_spam_words[:2])}")

        if dns_validation and dns_validation.get("mx", {}).get("is_send_only"):
            cat_scores[ThreatCategory.SPAM_RECONNAISSANCE] += 0.25
            reasons[ThreatCategory.SPAM_RECONNAISSANCE].append("Sender domain has no MX records (send-only burner domain).")

        # 6. EVALUATE LEGITIMATE BUSINESS EMAIL
        clean_auth = True
        if dns_validation:
            d_pass = dns_validation.get("alignment", {}).get("dmarc_pass", False)
            spf_auth = dns_validation.get("spf", {}).get("is_ip_authorized", True)
            if d_pass and spf_auth:
                cat_scores[ThreatCategory.LEGITIMATE] += 0.4
                reasons[ThreatCategory.LEGITIMATE].append("SPF and DKIM identifiers aligned with verified DMARC policy.")
            else:
                clean_auth = False

        if domain_intel:
            age = domain_intel.get("domain_age_days")
            if age and age > 365:
                cat_scores[ThreatCategory.LEGITIMATE] += 0.2
                reasons[ThreatCategory.LEGITIMATE].append(f"Established domain reputation (Age: {age} days).")
            elif domain_intel.get("is_newly_registered"):
                clean_auth = False

        if risk_score <= 0.15 and len(findings) == 0 and clean_auth:
            cat_scores[ThreatCategory.LEGITIMATE] += 0.6
            reasons[ThreatCategory.LEGITIMATE].append("Zero anomalous threat indicators or malicious artifacts detected.")

        # DETERMINE PRIMARY CATEGORY & CONFIDENCE
        # If all threat scores are 0, classify as Legitimate
        max_threat = max(
            cat_scores[ThreatCategory.CREDENTIAL_PHISHING],
            cat_scores[ThreatCategory.MALWARE_DELIVERY],
            cat_scores[ThreatCategory.CEO_IMPERSONATION],
            cat_scores[ThreatCategory.PAYMENT_DIVERSION],
            cat_scores[ThreatCategory.SPAM_RECONNAISSANCE],
        )

        if max_threat <= 0.20 and risk_score <= 0.20:
            primary = ThreatCategory.LEGITIMATE
            confidence = max(0.65, min(0.98, 1.0 - risk_score))
        else:
            # Sort categories by score
            sorted_cats = sorted(
                [c for c in ThreatCategory if c != ThreatCategory.LEGITIMATE],
                key=lambda c: cat_scores[c],
                reverse=True,
            )
            primary = sorted_cats[0]
            top_score = cat_scores[primary]
            # Normalize confidence between 0.60 and 0.98
            confidence = max(0.60, min(0.98, round(0.55 + (top_score * 0.35), 2)))

        # Build secondary ranked list
        secondary: List[Dict[str, Any]] = []
        for cat, score in sorted(cat_scores.items(), key=lambda x: x[1], reverse=True):
            if cat != primary and score > 0.15:
                sec_conf = max(0.20, min(0.85, round(score * 0.5, 2)))
                secondary.append({
                    "category": cat.value,
                    "label": CATEGORY_LABELS[cat],
                    "confidence": sec_conf,
                })

        justification_list = reasons.get(primary, [])
        if not justification_list:
            if primary == ThreatCategory.LEGITIMATE:
                justification_list = ["Clean protocol authentication and benign message content."]
            else:
                justification_list = [f"Heuristic pattern matches characteristic of {CATEGORY_LABELS[primary]}."]

        return ThreatClassificationResult(
            primary_category=primary.value,
            category_label=CATEGORY_LABELS[primary],
            confidence=confidence,
            secondary_categories=secondary[:3],
            justification=justification_list[:5],
            action_summary=CATEGORY_ACTIONS[primary],
        )
