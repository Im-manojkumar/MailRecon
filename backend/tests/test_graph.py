import uuid
import pytest
from httpx import AsyncClient

from app.detectors.base import FindingData
from app.graph.builder import IndicatorGraphBuilder, parse_email_address_and_domain
from app.models.case import Case, CaseStatus
from app.models.finding import SeverityLevel
from app.models.indicator import Indicator, IndicatorKind
from app.parser.email_parser import AttachmentData, ParsedEmailResult
from tests.conftest import TEST_ANALYST_ID


def test_parse_email_address_and_domain():
    e1, d1 = parse_email_address_and_domain("Alice Smith <alice@example.com>")
    assert e1 == "alice@example.com"
    assert d1 == "example.com"

    e2, d2 = parse_email_address_and_domain("admin@corp.internal")
    assert e2 == "admin@corp.internal"
    assert d2 == "corp.internal"

    e3, d3 = parse_email_address_and_domain("Invalid Address Without At")
    assert e3 is None
    assert d3 is None


def test_extract_indicators():
    case_id = uuid.uuid4()
    parsed = ParsedEmailResult(
        headers={
            "From": "CEO <ceo@examp1e.com>",
            "To": "accountant@firm.com",
            "Reply-To": "wire@offshore-bank.xyz",
        },
        body_text="Urgent invoice attached.",
        body_html="",
        raw_html="",
        blocked_images=[],
        attachments=[
            AttachmentData(
                filename="invoice.xlsm",
                content_type="application/vnd.ms-excel.sheet.macroEnabled.12",
                size=12000,
                sha256="1234567890abcdef" * 4,
                is_macro=True,
                is_inline=False,
                content_id=None,
            )
        ],
        urls=[
            {"url": "https://login.portal-update.top/auth", "domain": "login.portal-update.top"}
        ],
        auth_results={},
        received_chain=[{"hop": 1, "ip": "209.85.220.41"}],
    )
    qr_codes = [
        {
            "attachment_name": "scan_me.png",
            "decoded_text": "https://quish-attack.site/verify",
            "is_url": True,
        }
    ]

    indicators = IndicatorGraphBuilder.extract_indicators(case_id, parsed, qr_codes)
    kinds = {ind.kind for ind in indicators}
    values = {ind.value for ind in indicators}

    assert IndicatorKind.email in kinds
    assert IndicatorKind.domain in kinds
    assert IndicatorKind.ip in kinds
    assert IndicatorKind.url in kinds
    assert IndicatorKind.hash in kinds
    assert IndicatorKind.qr_url in kinds

    assert "ceo@examp1e.com" in values
    assert "examp1e.com" in values
    assert "accountant@firm.com" in values
    assert "wire@offshore-bank.xyz" in values
    assert "209.85.220.41" in values
    assert "https://login.portal-update.top/auth" in values
    assert "1234567890abcdef" * 4 in values
    assert "https://quish-attack.site/verify" in values


def test_build_graph_nodes_and_edges():
    case_id = uuid.uuid4()
    parsed = ParsedEmailResult(
        headers={
            "Subject": "URGENT: Executive Wire Transfer",
            "From": "CEO <ceo@examp1e.com>",
            "To": "cfo@firm.com",
            "Reply-To": "fraud@hacker.org",
        },
        body_text="Wire funds immediately.",
        body_html="",
        raw_html="",
        blocked_images=[],
        attachments=[
            AttachmentData(
                filename="payload.exe",
                content_type="application/octet-stream",
                size=5000,
                sha256="abcdef123456" * 5 + "abcd",
                is_macro=True,
                is_inline=False,
                content_id=None,
            )
        ],
        urls=[
            {"url": "https://phish.net/login", "domain": "phish.net"}
        ],
        auth_results={},
        received_chain=[{"hop": 1, "ip": "198.51.100.10"}],
    )
    findings = [
        FindingData(
            detector="identity_spoofing",
            severity=SeverityLevel.high,
            title="Typosquatting",
            detail="Domain examp1e.com mimics company",
            evidence_ref="headers.From",
            confidence=0.9,
        ),
        FindingData(
            detector="suspicious_attachment",
            severity=SeverityLevel.critical,
            title="Executable Attachment",
            detail="Payload payload.exe is an executable",
            evidence_ref="attachments[0].filename",
            confidence=0.98,
        ),
    ]

    graph = IndicatorGraphBuilder.build_graph(case_id, parsed, findings)
    node_ids = {n.id for n in graph.nodes}
    relationships = {e.relationship for e in graph.edges}

    # Verify key nodes exist
    assert f"case:{case_id}" in node_ids
    assert "email:ceo@examp1e.com" in node_ids
    assert "domain:examp1e.com" in node_ids
    assert "email:cfo@firm.com" in node_ids
    assert "email:fraud@hacker.org" in node_ids
    assert "domain:fraud@hacker.org" in node_ids or "domain:hacker.org" in node_ids
    assert "ip:198.51.100.10" in node_ids
    assert "url:https://phish.net/login" in node_ids
    assert "domain:phish.net" in node_ids
    assert f"file:{parsed.attachments[0].sha256[:12]}" in node_ids

    # Verify key edges exist
    assert "sent_by" in relationships
    assert "sent_to" in relationships
    assert "from_domain" in relationships
    assert "reply_to" in relationships
    assert "relayed_by" in relationships
    assert "contains_url" in relationships
    assert "hosted_by" in relationships
    assert "attaches_file" in relationships

    # Verify risk attribution on flagged nodes
    domain_node = next(n for n in graph.nodes if n.id == "domain:examp1e.com")
    assert domain_node.risk_level == "malicious"


@pytest.mark.asyncio
async def test_indicators_and_graph_api(async_client: AsyncClient, auth_headers: dict, db_session):
    case_id = uuid.uuid4()

    mock_graph = {
        "nodes": [
            {"id": f"case:{case_id}", "kind": "case", "value": str(case_id), "label": "Email: Test Case", "risk_level": "neutral"},
            {"id": "email:sender@domain.com", "kind": "email", "value": "sender@domain.com", "label": "sender@domain.com", "risk_level": "neutral"},
        ],
        "edges": [
            {"id": "e1", "source": f"case:{case_id}", "target": "email:sender@domain.com", "relationship": "sent_by", "label": "Sent By"}
        ],
    }

    case = Case(
        id=case_id,
        analyst_id=TEST_ANALYST_ID,
        filename="graph_test.eml",
        original_sha256="cc" * 32,
        original_size=1024,
        storage_key=f"{case_id}/graph_test.eml",
        status=CaseStatus.completed,
        metadata_json={"indicator_graph": mock_graph},
    )
    db_session.add(case)

    # Add Indicator DB records
    ind1 = Indicator(
        case_id=case_id,
        kind=IndicatorKind.email,
        value="sender@domain.com",
        context="Header: From",
    )
    ind2 = Indicator(
        case_id=case_id,
        kind=IndicatorKind.domain,
        value="domain.com",
        context="Sender Domain",
    )
    db_session.add(ind1)
    db_session.add(ind2)
    await db_session.commit()

    # 1. Test GET /api/cases/{id}/indicators
    resp_ind = await async_client.get(f"/api/cases/{case_id}/indicators", headers=auth_headers)
    assert resp_ind.status_code == 200
    ind_data = resp_ind.json()
    assert ind_data["total"] == 2
    assert len(ind_data["items"]) == 2
    assert ind_data["items"][0]["value"] in ["sender@domain.com", "domain.com"]

    # 2. Test GET /api/cases/{id}/graph
    resp_graph = await async_client.get(f"/api/cases/{case_id}/graph", headers=auth_headers)
    assert resp_graph.status_code == 200
    graph_data = resp_graph.json()
    assert len(graph_data["nodes"]) == 2
    assert len(graph_data["edges"]) == 1
    assert graph_data["edges"][0]["relationship"] == "sent_by"
