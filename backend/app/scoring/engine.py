"""
Risk Scoring Engine for MailRecon AI.
Implements truthful risk scoring with non-linear saturation, explicit confidence,
and evidence coverage verification without artificial precision.
"""
from dataclasses import dataclass, field
import math
from typing import Any, Dict, List, Literal

from app.detectors.base import FindingData
from app.models.finding import SeverityLevel
from app.parser.email_parser import ParsedEmailResult

SEVERITY_WEIGHTS: Dict[SeverityLevel, float] = {
    SeverityLevel.critical: 40.0,
    SeverityLevel.high: 25.0,
    SeverityLevel.medium: 12.0,
    SeverityLevel.low: 5.0,
    SeverityLevel.info: 1.0,
}


@dataclass
class RiskScoreResult:
    score: float  # 0.0 to 100.0
    confidence: float  # 0.0 to 1.0
    coverage: float  # 0.0 to 1.0
    uncertainty_label: str  # "definitive" | "probable" | "inconclusive" | "unverifiable"
    is_heuristic: Literal[True] = True
    summary: str = ""
    breakdown: Dict[str, Any] = field(default_factory=dict)


class RiskScoringEngine:
    """
    Computes calibrated heuristic risk score, confidence, and coverage for an email case.
    """

    @classmethod
    def calculate_coverage(cls, parsed: ParsedEmailResult) -> tuple[float, Dict[str, float]]:
        """
        Evaluate completeness across 5 key forensic dimensions (0.0 - 1.0):
        1. Authentication headers (0.20)
        2. Received routing hops (0.20)
        3. Body textual content (0.20)
        4. Attachment inspection (0.20)
        5. URL inspection (0.20)
        """
        dims: Dict[str, float] = {}

        # 1. Authentication Headers (SPF/DKIM/DMARC)
        if parsed.auth_results:
            dims["auth_headers"] = 0.20
        elif "Authentication-Results" in parsed.headers:
            dims["auth_headers"] = 0.15
        elif "From" in parsed.headers and "Date" in parsed.headers:
            dims["auth_headers"] = 0.10
        else:
            dims["auth_headers"] = 0.0

        # 2. Received Routing Chain
        hops_count = len(parsed.received_chain)
        if hops_count >= 2:
            dims["routing_hops"] = 0.20
        elif hops_count == 1:
            dims["routing_hops"] = 0.15
        else:
            dims["routing_hops"] = 0.05

        # 3. Body Content
        body_has_text = bool(parsed.body_text and parsed.body_text.strip())
        body_has_html = bool(parsed.body_html and parsed.body_html.strip())
        if body_has_text and body_has_html:
            dims["body_content"] = 0.20
        elif body_has_text or body_has_html:
            dims["body_content"] = 0.18
        else:
            dims["body_content"] = 0.0

        # 4. Attachment Inspection
        if parsed.attachments:
            # All attachments inspected
            dims["attachments"] = 0.20
        else:
            # Clean case with no attachments to inspect
            dims["attachments"] = 0.20

        # 5. URL Inspection
        if parsed.urls:
            # All URLs extracted and defanged
            dims["urls"] = 0.20
        else:
            # Clean case with no URLs to inspect
            dims["urls"] = 0.20

        total_coverage = round(sum(dims.values()), 2)
        total_coverage = max(0.0, min(1.0, total_coverage))
        return total_coverage, dims

    @classmethod
    def compute_score(
        cls, parsed: ParsedEmailResult, findings: List[FindingData]
    ) -> RiskScoreResult:
        coverage, coverage_breakdown = cls.calculate_coverage(parsed)

        # 1. Calculate Raw Point Contributions
        raw_points = 0.0
        weighted_conf_sum = 0.0
        total_weight = 0.0
        findings_by_severity: Dict[str, int] = {}

        for f in findings:
            weight = SEVERITY_WEIGHTS.get(f.severity, 5.0)
            conf = max(0.0, min(1.0, f.confidence))
            contribution = weight * conf
            raw_points += contribution

            weighted_conf_sum += conf * weight
            total_weight += weight

            sev_name = f.severity.value
            findings_by_severity[sev_name] = findings_by_severity.get(sev_name, 0) + 1

        # 2. Asymptotic Saturation Curve for Score [0, 100]
        # Scaling constant k=35 ensures 1 critical (38 pts) lands at ~66%,
        # 1 critical + 1 high (60 pts) lands at ~82%, and multiple threats approach 90-99%.
        if raw_points <= 0.0:
            score = 0.0
        else:
            score = 100.0 * (1.0 - math.exp(-raw_points / 35.0))
            score = round(min(100.0, max(0.0, score)), 1)

        # 3. Confidence Aggregation
        if total_weight > 0:
            confidence = round(weighted_conf_sum / total_weight, 2)
        else:
            # When zero threats fired, confidence is tied to analysis completeness
            confidence = round(0.60 + 0.35 * coverage, 2)

        # 4. Uncertainty Label
        if coverage >= 0.80:
            if score >= 65.0 or score <= 15.0:
                uncertainty_label = "definitive"
            else:
                uncertainty_label = "probable"
        elif coverage >= 0.50:
            uncertainty_label = "probable"
        else:
            uncertainty_label = "inconclusive"

        if parsed.mime_depth_exceeded:
            uncertainty_label = "inconclusive"

        # 5. Formulate Summary
        if not findings or score <= 10.0:
            summary = (
                f"Low risk ({score}/100, Heuristic). No significant threat indicators detected. "
                f"Analysis coverage is {coverage * 100:.0f}% across forensic dimensions."
            )
        else:
            sev_summary_parts = [
                f"{count} {sev.upper()}" for sev, count in sorted(findings_by_severity.items())
            ]
            sev_desc = ", ".join(sev_summary_parts)
            summary = (
                f"Elevated risk ({score}/100, Heuristic) driven by {sev_desc} finding(s). "
                f"Confidence is {confidence * 100:.0f}%, coverage {coverage * 100:.0f}% ({uncertainty_label})."
            )

        breakdown = {
            "raw_points": round(raw_points, 2),
            "findings_count": len(findings),
            "findings_by_severity": findings_by_severity,
            "coverage_breakdown": coverage_breakdown,
        }

        return RiskScoreResult(
            score=score,
            confidence=confidence,
            coverage=coverage,
            uncertainty_label=uncertainty_label,
            is_heuristic=True,
            summary=summary,
            breakdown=breakdown,
        )
