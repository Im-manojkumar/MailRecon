"""
MailRecon AI — Evasive Obfuscation Detector
Detects adversarial evasive maneuvers including Right-to-Left Override (RLO),
zero-width character injection (keyword evasion), and mixed-script homoglyphs.
"""

from typing import List

from app.detectors.base import BaseDetector, FindingData
from app.forensics.obfuscation import ObfuscationAnalyzer
from app.models.finding import SeverityLevel
from app.parser.email_parser import ParsedEmailResult


class EvasiveObfuscationDetector(BaseDetector):
    name = "evasive_obfuscation"

    def analyze(self, parsed: ParsedEmailResult) -> List[FindingData]:
        findings: List[FindingData] = []

        # 1. Inspect Attachment Filenames for RLO & Extension Obfuscation
        for idx, att in enumerate(parsed.attachments):
            is_evasive, sanitized_name, trick_desc = ObfuscationAnalyzer.inspect_filename(att.filename)
            if is_evasive:
                findings.append(FindingData(
                    detector=self.name,
                    severity=SeverityLevel.critical,
                    title=f"Right-to-Left Override (RLO) File Spoofing ({att.filename})",
                    detail=(
                        f"The attachment '{att.filename}' employs an adversarial {trick_desc}. "
                        f"When rendered in email clients or operating systems, this character inverts the filename "
                        f"direction to disguise a dangerous executable as a harmless file like '{sanitized_name}'."
                    ),
                    evidence_ref=f"attachments[{idx}].filename",
                    confidence=0.99,
                    raw_evidence={
                        "raw_filename": att.filename,
                        "sanitized_filename": sanitized_name,
                        "sha256": att.sha256,
                        "trick": trick_desc,
                    }
                ))

        # 2. Inspect Headers (Subject, From, Reply-To)
        headers = parsed.headers or {}
        for header_name in ["subject", "from", "reply_to"]:
            header_val = headers.get(header_name, "")
            if not header_val or not isinstance(header_val, str):
                continue

            analysis = ObfuscationAnalyzer.analyze_text(header_val)
            if analysis.has_evasion:
                # Homoglyphs / Mixed script in header
                if analysis.mixed_script_tokens or analysis.homoglyphs_detected:
                    findings.append(FindingData(
                        detector=self.name,
                        severity=SeverityLevel.high,
                        title=f"Mixed-Script Homoglyph Spoofing in {header_name.title()}",
                        detail=(
                            f"The email {header_name.title()} contains {len(analysis.homoglyphs_found)} homoglyph character(s) "
                            f"and mixed-script tokens ({', '.join(analysis.mixed_script_tokens[:3])}). "
                            "Adversaries substitute Cyrillic or Greek lookalikes to impersonate trusted brands or bypass reputation filters."
                        ),
                        evidence_ref=f"headers.{header_name}",
                        confidence=0.96,
                        raw_evidence={
                            "header": header_name,
                            "original_value": header_val,
                            "normalized_value": analysis.normalized_text,
                            "mixed_tokens": analysis.mixed_script_tokens,
                            "homoglyphs_count": len(analysis.homoglyphs_found),
                        }
                    ))

                # Zero-width characters in subject
                if analysis.zero_width_count >= 1:
                    findings.append(FindingData(
                        detector=self.name,
                        severity=SeverityLevel.high,
                        title=f"Invisible / Zero-Width Characters in {header_name.title()}",
                        detail=(
                            f"The {header_name.title()} header contains {analysis.zero_width_count} invisible zero-width character(s). "
                            "This technique is used to bypass anti-spam regex filters while remaining invisible to the victim."
                        ),
                        evidence_ref=f"headers.{header_name}",
                        confidence=0.95,
                        raw_evidence={
                            "header": header_name,
                            "zero_width_count": analysis.zero_width_count,
                            "normalized_value": analysis.normalized_text,
                        }
                    ))

        # 3. Inspect Body Text
        body_text = parsed.body_text or ""
        if body_text:
            body_analysis = ObfuscationAnalyzer.analyze_text(body_text)
            if body_analysis.zero_width_count >= 2:
                findings.append(FindingData(
                    detector=self.name,
                    severity=SeverityLevel.high,
                    title="Zero-Width Steganography & Keyword Splicing in Body",
                    detail=(
                        f"Detected {body_analysis.zero_width_count} invisible zero-width characters strategically inserted "
                        "inside the email body text. Attackers use zero-width spaces (e.g., U+200B) to slice keywords "
                        "and evade lexical analysis rules."
                    ),
                    evidence_ref="body.text.zero_width",
                    confidence=0.94,
                    raw_evidence={
                        "zero_width_count": body_analysis.zero_width_count,
                        "sample_positions": [c["position"] for c in body_analysis.zero_width_chars[:10]],
                        "normalized_preview": body_analysis.normalized_text[:300],
                    }
                ))

            if body_analysis.mixed_script_tokens:
                findings.append(FindingData(
                    detector=self.name,
                    severity=SeverityLevel.medium,
                    title="Mixed-Script Homoglyph Tokens in Email Body",
                    detail=(
                        f"Detected {len(body_analysis.mixed_script_tokens)} token(s) blending Latin and non-Latin lookalike scripts "
                        f"in the body text ({', '.join(body_analysis.mixed_script_tokens[:5])})."
                    ),
                    evidence_ref="body.text.homoglyphs",
                    confidence=0.88,
                    raw_evidence={
                        "mixed_tokens": body_analysis.mixed_script_tokens,
                        "homoglyphs_count": len(body_analysis.homoglyphs_found),
                    }
                ))

        return findings
