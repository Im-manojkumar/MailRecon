"""
Unit and API integration tests for Forensic Reporting Engine.
"""
from datetime import datetime, timezone
import hashlib
import json
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.case import Case, CaseStatus
from app.models.finding import Finding, SeverityLevel
from app.models.parsed_email import ParsedEmail
from app.models.report import Report, ReportFormat
from app.reporting.generator import ForensicReportGenerator
from app.storage.base import EvidenceStore
from app.storage.deps import get_evidence_store
from tests.conftest import TEST_ANALYST_ID


@pytest.mark.asyncio
async def test_generate_json_report():
    case = Case(
        id=uuid.uuid4(),
        analyst_id=TEST_ANALYST_ID,
        filename="test_phish.eml",
        original_sha256="abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc",
        original_size=1024,
        status=CaseStatus.completed,
        created_at=datetime.now(timezone.utc),
        metadata_json={
            "risk_score": {
                "score": 85.0,
                "confidence": 0.95,
                "coverage": 0.8,
                "uncertainty_label": "definitive",
                "is_heuristic": True,
                "summary": "High threat detected.",
            }
        },
    )

    finding = Finding(
        id=uuid.uuid4(),
        case_id=case.id,
        detector="test_detector",
        severity=SeverityLevel.high,
        title="Suspicious Anchor",
        detail="Anchor text does not match target host",
        evidence_ref="urls[0]",
        confidence=0.9,
    )

    report_bytes, sha256_hash = ForensicReportGenerator.generate_json_report(
        case=case,
        parsed=None,
        findings=[finding],
    )

    assert isinstance(report_bytes, bytes)
    assert hashlib.sha256(report_bytes).hexdigest() == sha256_hash

    data = json.loads(report_bytes.decode("utf-8"))
    assert data["report_metadata"]["case_id"] == str(case.id)
    assert data["evidence_target"]["filename"] == "test_phish.eml"
    assert data["threat_assessment"]["score"] == 85.0
    assert len(data["findings"]) == 1
    assert data["findings"][0]["title"] == "Suspicious Anchor"


@pytest.mark.asyncio
async def test_generate_html_report():
    case = Case(
        id=uuid.uuid4(),
        analyst_id=TEST_ANALYST_ID,
        filename="wire_transfer.eml",
        original_sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        original_size=2048,
        status=CaseStatus.completed,
        created_at=datetime.now(timezone.utc),
        metadata_json={
            "risk_score": {
                "score": 92.0,
                "confidence": 0.98,
                "coverage": 1.0,
                "uncertainty_label": "definitive",
                "is_heuristic": True,
                "summary": "Urgent wire transfer coercion detected.",
            },
            "ai_analysis": {
                "executive_summary": "Executive impersonation BEC attack targeting wire transfer.",
                "attack_vector": "Business Email Compromise (BEC)",
                "threat_actor_tactics": ["Executive Display Name Spoofing", "Financial Urgency"],
                "recommended_actions": ["Block sender domain", "Confirm out-of-band"],
                "is_grounded": True,
            },
            "route_analysis": {
                "hops": [
                    {
                        "hop": 1,
                        "by_node": "mx.victim.com",
                        "ip": "198.51.100.1",
                        "geoip": {"country": "US", "city": "Ashburn", "asn": "AS12345"},
                        "delay_display": "Origin Ingestion",
                    }
                ]
            },
        },
    )

    finding = Finding(
        id=uuid.uuid4(),
        case_id=case.id,
        detector="bec_detector",
        severity=SeverityLevel.critical,
        title="CEO Wire Transfer Lure",
        detail="Coercive payment request with secrecy demands",
        evidence_ref="headers.Subject",
        confidence=0.99,
    )

    report_bytes, sha256_hash = ForensicReportGenerator.generate_html_report(
        case=case,
        parsed=None,
        findings=[finding],
    )

    assert isinstance(report_bytes, bytes)
    assert hashlib.sha256(report_bytes).hexdigest() == sha256_hash

    html_str = report_bytes.decode("utf-8")
    assert "<!DOCTYPE html>" in html_str
    assert "Forensic Email Incident Report" in html_str
    assert "wire_transfer.eml" in html_str
    assert "CEO Wire Transfer Lure" in html_str
    assert "Executive impersonation BEC attack" in html_str
    assert sha256_hash in html_str or "Cryptographically Sealed" in html_str


@pytest.mark.asyncio
async def test_report_api_endpoints(async_client: AsyncClient, db_session: AsyncSession, auth_headers: dict):
    # 1. Create a test case in DB
    case_id = uuid.uuid4()
    case = Case(
        id=case_id,
        analyst_id=TEST_ANALYST_ID,
        filename="invoice.eml",
        original_sha256="deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
        original_size=500,
        storage_key=f"cases/{case_id}.eml",
        status=CaseStatus.completed,
        metadata_json={
            "risk_score": {
                "score": 60.0,
                "confidence": 0.85,
                "coverage": 0.7,
                "uncertainty_label": "probable",
                "is_heuristic": True,
                "summary": "Suspicious invoice attachment.",
            }
        },
    )
    db_session.add(case)
    await db_session.commit()

    # 2. Generate HTML report
    res_html = await async_client.post(f"/api/cases/{case_id}/report?format=html", headers=auth_headers)
    assert res_html.status_code == 201
    report_html_data = res_html.json()
    assert report_html_data["format"] == "html"
    assert report_html_data["case_id"] == str(case_id)
    assert len(report_html_data["integrity_sha256"]) == 64
    html_report_id = report_html_data["id"]

    # 3. Generate JSON report
    res_json = await async_client.post(f"/api/cases/{case_id}/report?format=json", headers=auth_headers)
    assert res_json.status_code == 201
    report_json_data = res_json.json()
    assert report_json_data["format"] == "json"
    assert report_json_data["case_id"] == str(case_id)
    assert len(report_json_data["integrity_sha256"]) == 64
    json_report_id = report_json_data["id"]

    # 4. List reports
    res_list = await async_client.get(f"/api/cases/{case_id}/reports", headers=auth_headers)
    assert res_list.status_code == 200
    list_data = res_list.json()
    assert list_data["total"] >= 2
    r_ids = [r["id"] for r in list_data["items"]]
    assert html_report_id in r_ids
    assert json_report_id in r_ids

    # 5. Download HTML report
    res_dl = await async_client.get(f"/api/cases/{case_id}/reports/{html_report_id}", headers=auth_headers)
    assert res_dl.status_code == 200
    assert "text/html" in res_dl.headers["content-type"]
    assert res_dl.headers["x-report-sha256"] == report_html_data["integrity_sha256"]
    assert b"<!DOCTYPE html>" in res_dl.content

    # 6. Download JSON report
    res_dl_json = await async_client.get(f"/api/cases/{case_id}/reports/{json_report_id}", headers=auth_headers)
    assert res_dl_json.status_code == 200
    assert "application/json" in res_dl_json.headers["content-type"]
    assert res_dl_json.headers["x-report-sha256"] == report_json_data["integrity_sha256"]
    loaded_json = json.loads(res_dl_json.content)
    assert loaded_json["report_metadata"]["case_id"] == str(case_id)


@pytest.mark.asyncio
async def test_download_report_tamper_detection(async_client: AsyncClient, db_session: AsyncSession, auth_headers: dict):
    case_id = uuid.uuid4()
    case = Case(
        id=case_id,
        analyst_id=TEST_ANALYST_ID,
        filename="tamper_test.eml",
        original_sha256="ffffffff12345678deadbeef12345678deadbeef12345678deadbeef12345678",
        original_size=500,
        storage_key=f"cases/{case_id}.eml",
        status=CaseStatus.completed,
    )
    db_session.add(case)
    await db_session.commit()

    # Generate HTML report
    res = await async_client.post(f"/api/cases/{case_id}/report?format=html", headers=auth_headers)
    assert res.status_code == 201
    rep_id = res.json()["id"]

    # Retrieve storage and tamper with file
    from app.main import app
    storage = app.dependency_overrides[get_evidence_store]()
    storage_key = f"reports/{case_id}/{rep_id}.html"
    await storage.put(storage_key, b"TAMPERED CONTENT CORRUPTING CHECKSUM")

    # Attempt download -> should return 409 Conflict (tamper detection)
    res_tampered = await async_client.get(f"/api/cases/{case_id}/reports/{rep_id}", headers=auth_headers)
    assert res_tampered.status_code == 409
    assert "tampering detected" in res_tampered.json()["detail"].lower()
