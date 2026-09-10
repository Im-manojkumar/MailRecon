import pytest
from httpx import AsyncClient
import uuid

from app.detectors.base import FindingData
from app.models.case import Case, CaseStatus
from app.models.finding import SeverityLevel
from app.parser.email_parser import ParsedEmailResult
from app.scoring.engine import RiskScoringEngine
from tests.conftest import TEST_ANALYST_ID


def test_scoring_clean_email():
    clean_parsed = ParsedEmailResult(
        headers={"Subject": "Team Meeting", "From": "alice@corp.com", "Date": "2026-09-10", "Authentication-Results": "spf=pass"},
        body_text="See everyone at 10 AM.",
        body_html="<p>See everyone at 10 AM.</p>",
        raw_html="",
        blocked_images=[],
        attachments=[],
        urls=[],
        auth_results={"spf": "pass"},
        received_chain=[{"hop": 1, "from": "mail.corp.com"}, {"hop": 2, "from": "internal.corp.com"}],
    )

    result = RiskScoringEngine.compute_score(clean_parsed, [])
    assert result.score == 0.0
    assert result.coverage >= 0.8
    assert result.confidence >= 0.8
    assert result.uncertainty_label == "definitive"
    assert result.is_heuristic is True
    assert "Low risk" in result.summary


def test_scoring_bec_urgent_threat():
    bec_parsed = ParsedEmailResult(
        headers={"Subject": "URGENT: Wire Transfer", "From": "ceo@examp1e.com", "Date": "2026-09-10"},
        body_text="Send $45,000 to vendor immediately.",
        body_html="",
        raw_html="",
        blocked_images=[],
        attachments=[],
        urls=[],
        auth_results={},
        received_chain=[{"hop": 1, "from": "external.net"}],
    )

    findings = [
        FindingData(
            detector="bec_intent",
            severity=SeverityLevel.high,
            title="BEC Wire Transfer Demand",
            detail="Urgent wire transfer combined with secrecy pressure",
            evidence_ref="body_text",
            confidence=0.92,
        ),
        FindingData(
            detector="identity_spoofing",
            severity=SeverityLevel.high,
            title="Typosquatting Lookalike Domain",
            detail="Domain examp1e.com mimics legitimate brand",
            evidence_ref="headers.From",
            confidence=0.88,
        ),
    ]

    result = RiskScoringEngine.compute_score(bec_parsed, findings)
    assert result.score >= 70.0
    assert result.confidence >= 0.85
    assert result.uncertainty_label == "definitive"
    assert result.is_heuristic is True
    assert "Elevated risk" in result.summary


def test_scoring_attachment_critical_threat():
    att_parsed = ParsedEmailResult(
        headers={"Subject": "Invoice Attached", "From": "billing@malicious.xyz", "Date": "2026-09-10"},
        body_text="Please find attached invoice.",
        body_html="",
        raw_html="",
        blocked_images=[],
        attachments=[],
        urls=[],
        auth_results={},
        received_chain=[{"hop": 1}],
    )

    findings = [
        FindingData(
            detector="suspicious_attachment",
            severity=SeverityLevel.critical,
            title="Weaponized Executable",
            detail="Double extension executable detected: invoice.pdf.exe",
            evidence_ref="attachments[0].filename",
            confidence=0.95,
        )
    ]

    result = RiskScoringEngine.compute_score(att_parsed, findings)
    assert result.score >= 60.0
    assert result.breakdown["findings_by_severity"]["critical"] == 1
    assert result.is_heuristic is True


def test_scoring_degraded_coverage():
    degraded_parsed = ParsedEmailResult(
        headers={},
        body_text="",
        body_html="",
        raw_html="",
        blocked_images=[],
        attachments=[],
        urls=[],
        auth_results={},
        received_chain=[],
    )

    coverage, dims = RiskScoringEngine.calculate_coverage(degraded_parsed)
    assert coverage < 0.60
    assert dims["auth_headers"] == 0.0
    assert dims["body_content"] == 0.0

    result = RiskScoringEngine.compute_score(degraded_parsed, [])
    assert result.uncertainty_label == "inconclusive"


def test_scoring_mime_depth_exceeded_uncertainty():
    parsed = ParsedEmailResult(
        headers={"Subject": "Deeply nested email", "From": "a@b.com", "Date": "2026-09-10"},
        body_text="Sample text",
        body_html="",
        raw_html="",
        blocked_images=[],
        attachments=[],
        urls=[],
        auth_results={},
        received_chain=[{"hop": 1}],
        mime_depth_exceeded=True,
    )

    result = RiskScoringEngine.compute_score(parsed, [])
    assert result.uncertainty_label == "inconclusive"


@pytest.mark.asyncio
async def test_get_case_score_api(async_client: AsyncClient, auth_headers: dict, db_session):
    # 1. Analyzed Case with Risk Score
    case_id = uuid.uuid4()
    mock_score = {
        "score": 84.5,
        "confidence": 0.91,
        "coverage": 0.95,
        "uncertainty_label": "definitive",
        "is_heuristic": True,
        "summary": "Elevated risk (84.5/100, Heuristic) driven by 2 HIGH findings.",
    }

    case = Case(
        id=case_id,
        analyst_id=TEST_ANALYST_ID,
        filename="threat.eml",
        original_sha256="ff" * 32,
        original_size=2048,
        storage_key=f"{case_id}/threat.eml",
        status=CaseStatus.completed,
        metadata_json={"risk_score": mock_score},
    )
    db_session.add(case)
    await db_session.commit()

    resp = await async_client.get(f"/api/cases/{case_id}/score", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] == 84.5
    assert data["confidence"] == 0.91
    assert data["coverage"] == 0.95
    assert data["uncertainty_label"] == "definitive"
    assert data["is_heuristic"] is True

    # 2. Unanalyzed Case
    unanalyzed_id = uuid.uuid4()
    unanalyzed_case = Case(
        id=unanalyzed_id,
        analyst_id=TEST_ANALYST_ID,
        filename="pending.eml",
        original_sha256="ee" * 32,
        original_size=1024,
        storage_key=f"{unanalyzed_id}/pending.eml",
        status=CaseStatus.pending,
        metadata_json={},
    )
    db_session.add(unanalyzed_case)
    await db_session.commit()

    resp_pending = await async_client.get(f"/api/cases/{unanalyzed_id}/score", headers=auth_headers)
    assert resp_pending.status_code == 200
    data_pending = resp_pending.json()
    assert data_pending["score"] == 0.0
    assert data_pending["uncertainty_label"] == "not_yet_analyzed"
    assert data_pending["is_heuristic"] is True
