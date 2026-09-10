import io
import uuid
import pytest
import qrcode
from httpx import AsyncClient

from app.enrichment.geoip import MockGeoIPProvider, is_private_or_reserved_ip
from app.enrichment.qr_decoder import QrCodeDecoder
from app.enrichment.route_analyzer import RouteAnalyzer
from app.models.case import Case, CaseStatus
from app.parser.email_parser import AttachmentData
from tests.conftest import TEST_ANALYST_ID


def test_geoip_classification():
    provider = MockGeoIPProvider()

    # 1. Private RFC 1918 IPs
    assert is_private_or_reserved_ip("192.168.1.1") is True
    assert is_private_or_reserved_ip("10.50.0.1") is True
    assert is_private_or_reserved_ip("172.16.5.1") is True
    assert is_private_or_reserved_ip("127.0.0.1") is True
    assert is_private_or_reserved_ip("169.254.1.1") is True

    loc_lan = provider.lookup("192.168.1.1")
    assert loc_lan.is_private is True
    assert loc_lan.country_code == "LAN"
    assert loc_lan.latitude is None

    # 2. Known Public IPs
    assert is_private_or_reserved_ip("209.85.220.41") is False
    loc_google = provider.lookup("209.85.220.41")
    assert loc_google.is_private is False
    assert loc_google.country_code == "US"
    assert loc_google.org == "Google LLC"
    assert loc_google.latitude is not None
    assert loc_google.longitude is not None

    loc_de = provider.lookup("185.100.5.2")
    assert loc_de.is_private is False
    assert loc_de.country_code == "DE"

    # 3. Arbitrary Public IP
    loc_pub = provider.lookup("8.8.4.4")
    assert loc_pub.is_private is False
    assert loc_pub.latitude is not None


def test_route_analyzer_delays_and_totals():
    chain = [
        {
            "hop": 1,
            "from": "laptop.client.com",
            "by": "smtp.client.com",
            "ip": "192.168.1.50",
            "timestamp_iso": "2026-09-10T10:00:00+00:00",
        },
        {
            "hop": 2,
            "from": "smtp.client.com",
            "by": "mx.google.com",
            "ip": "209.85.220.41",
            "timestamp_iso": "2026-09-10T10:00:04+00:00",
        },
        {
            "hop": 3,
            "from": "mx.google.com",
            "by": "mail.corporate.com",
            "ip": "10.0.0.10",
            "timestamp_iso": "2026-09-10T10:00:09+00:00",
        },
    ]

    result = RouteAnalyzer.analyze(chain)
    assert len(result.hops) == 3
    assert result.total_transit_seconds == 9.0

    # Hop 1 delay is 0
    assert result.hops[0].delay_seconds == 0.0
    assert result.hops[0].geoip["is_private"] is True

    # Hop 2 delay is 4.0s
    assert result.hops[1].delay_seconds == 4.0
    assert result.hops[1].geoip["is_private"] is False
    assert result.hops[1].geoip["country_code"] == "US"

    # Hop 3 delay is 5.0s
    assert result.hops[2].delay_seconds == 5.0
    assert len(result.anomalies) == 0


def test_route_analyzer_negative_delay_anomaly():
    chain = [
        {
            "hop": 1,
            "from": "sender.com",
            "by": "relay1.com",
            "timestamp_iso": "2026-09-10T10:15:00+00:00",
        },
        {
            "hop": 2,
            "from": "relay1.com",
            "by": "relay2.com",
            "timestamp_iso": "2026-09-10T10:10:00+00:00",  # -5 minutes!
        },
    ]

    result = RouteAnalyzer.analyze(chain)
    assert len(result.anomalies) == 1
    assert "Negative transit delay" in result.anomalies[0]


def test_qr_code_decoding_and_defanging():
    # Generate synthetic QR code
    raw_url = "https://login.secure-portal-auth.xyz/verify?id=9821"
    qr_img = qrcode.make(raw_url)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    img_bytes = buf.getvalue()

    results = QrCodeDecoder.decode_image_bytes(img_bytes, filename="inline_qr.png", content_id="qr123")
    assert len(results) == 1
    qr = results[0]
    assert qr.attachment_name == "inline_qr.png"
    assert qr.content_id == "qr123"
    assert qr.decoded_text == raw_url
    assert qr.is_url is True
    assert qr.defanged_text == "hxxps://login[.]secure-portal-auth[.]xyz/verify?id=9821"
    assert qr.rect["width"] > 0
    assert qr.rect["height"] > 0


def test_qr_code_oversized_image_rejection():
    # Threat T10 defense test: Oversized image payload
    fake_bomb = b"0" * 15_000_000  # 15MB exceeds 10MB limit
    results = QrCodeDecoder.decode_image_bytes(fake_bomb, filename="bomb.png")
    assert results == []


@pytest.mark.asyncio
async def test_route_and_qr_api_endpoints(async_client: AsyncClient, auth_headers: dict, db_session):
    case_id = uuid.uuid4()
    mock_route = {
        "hops": [
            {"hop_number": 1, "from_host": "src.net", "by_host": "dst.net", "ip": "209.85.1.1", "delay_seconds": 2.5, "geoip": {"country": "US"}}
        ],
        "total_transit_seconds": 2.5,
        "anomalies": [],
    }
    mock_qr = [
        {
            "attachment_name": "login_qr.png",
            "content_id": "cid1",
            "decoded_text": "https://evil.com/auth",
            "defanged_text": "hxxps://evil[.]com/auth",
            "is_url": True,
            "rect": {"left": 10, "top": 10, "width": 100, "height": 100},
        }
    ]

    case = Case(
        id=case_id,
        analyst_id=TEST_ANALYST_ID,
        filename="quishing.eml",
        original_sha256="aa" * 32,
        original_size=4096,
        storage_key=f"{case_id}/quishing.eml",
        status=CaseStatus.completed,
        metadata_json={
            "route_analysis": mock_route,
            "qr_codes": mock_qr,
        },
    )
    db_session.add(case)
    await db_session.commit()

    # 1. Test GET /api/cases/{id}/route
    resp_route = await async_client.get(f"/api/cases/{case_id}/route", headers=auth_headers)
    assert resp_route.status_code == 200
    route_data = resp_route.json()
    assert len(route_data["hops"]) == 1
    assert route_data["total_transit_seconds"] == 2.5

    # 2. Test GET /api/cases/{id}/qr-codes
    resp_qr = await async_client.get(f"/api/cases/{case_id}/qr-codes", headers=auth_headers)
    assert resp_qr.status_code == 200
    qr_data = resp_qr.json()
    assert len(qr_data) == 1
    assert qr_data[0]["attachment_name"] == "login_qr.png"
    assert qr_data[0]["is_url"] is True
