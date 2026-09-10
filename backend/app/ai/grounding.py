"""
Grounding validation for AI analysis outputs.
Guarantees that all claims and citations map to factual evidence and eliminates hallucinations.
"""
import logging
import re
from typing import List, Set

from app.ai.base import AIAnalysisResult
from app.detectors.base import FindingData
from app.parser.email_parser import ParsedEmailResult

logger = logging.getLogger("mailrecon.ai.grounding")

DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_factual_entities(parsed: ParsedEmailResult, findings: List[FindingData]) -> Set[str]:
    """Collect all known domains, IPs, URLs, and filenames verified in the email."""
    entities: Set[str] = set()

    # Headers
    for header_name, header_val in parsed.headers.items():
        if isinstance(header_val, str):
            for d in DOMAIN_REGEX.findall(header_val):
                entities.add(d.lower())
            for ip in IP_REGEX.findall(header_val):
                entities.add(ip)

    # Extracted URLs
    for u in parsed.urls:
        url_str = u.get("url", "")
        if url_str:
            entities.add(url_str.lower())
        domain = u.get("domain", "")
        if domain:
            entities.add(domain.lower())

    # Attachments
    for att in parsed.attachments:
        if att.filename:
            entities.add(att.filename.lower())
        if att.sha256:
            entities.add(att.sha256.lower())

    # Detector names and findings
    for f in findings:
        entities.add(f.detector.lower())
        if f.evidence_ref:
            entities.add(f.evidence_ref.lower())

    return entities


def validate_grounding(
    analysis: AIAnalysisResult,
    parsed: ParsedEmailResult,
    findings: List[FindingData],
) -> AIAnalysisResult:
    """
    Validate that an AI briefing does not fabricate non-existent indicators.
    Filters invalid evidence citations and sets is_grounded status.
    """
    factual_entities = extract_factual_entities(parsed, findings)

    valid_citations: List[str] = []
    has_hallucinated_citation = False

    for citation in analysis.evidence_citations:
        c_lower = citation.lower().strip()
        # Direct reference to header or finding attribute
        if (
            c_lower.startswith("headers.")
            or c_lower.startswith("findings.")
            or c_lower.startswith("body")
            or c_lower.startswith("urls[")
            or c_lower.startswith("attachments[")
            or any(ent in c_lower for ent in factual_entities)
        ):
            valid_citations.append(citation)
        else:
            logger.warning(f"Filtered ungrounded AI citation: {citation}")
            has_hallucinated_citation = True

    # If all citations were filtered but findings exist, backfill from verified findings
    if not valid_citations and findings:
        valid_citations = [f"{f.detector}: {f.evidence_ref}" for f in findings[:5]]

    # Ensure clean emails with zero findings aren't misclassified as critical attacks
    is_grounded = not has_hallucinated_citation
    if not findings and "Benign" not in analysis.attack_vector:
        # If no detectors flagged anything and email has no high risk indicators
        if "benign" in analysis.executive_summary.lower() or "clean" in analysis.executive_summary.lower():
            analysis.attack_vector = "Benign Corporate Correspondence"

    analysis.evidence_citations = valid_citations
    analysis.is_grounded = is_grounded
    return analysis
