from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import pytest

from app.enrichment.domain_intel import DomainIntelService


def test_mock_domains_lookup():
    DomainIntelService._cache.clear()

    # 1. New phishing domain
    phish_prof = DomainIntelService.lookup("phish-update-login.xyz")
    assert phish_prof.domain == "phish-update-login.xyz"
    assert phish_prof.is_newly_registered is True
    assert phish_prof.risk_level == "critical"
    assert phish_prof.registrar == "NameCheap, Inc."
    assert phish_prof.domain_age_days == 3

    # 2. Established benign domain
    legit_prof = DomainIntelService.lookup("google.com")
    assert legit_prof.domain == "google.com"
    assert legit_prof.is_newly_registered is False
    assert legit_prof.risk_level == "low"
    assert legit_prof.domain_age_days is not None
    assert legit_prof.domain_age_days > 1000


def test_rdap_mock_response_parsing():
    DomainIntelService._cache.clear()

    now_utc = datetime.now(timezone.utc)
    created_dt = now_utc - timedelta(days=12)
    created_iso = created_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_iso = (now_utc + timedelta(days=350)).strftime("%Y-%m-%dT%H:%M:%SZ")

    mock_rdap_json = {
        "events": [
            {"eventAction": "registration", "eventDate": created_iso},
            {"eventAction": "expiration", "eventDate": expires_iso},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "GoDaddy.com, LLC"],
                    ],
                ],
            }
        ],
        "status": ["active", "clientTransferProhibited"],
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_rdap_json

    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value = mock_client

        prof = DomainIntelService.lookup("brand-new-fake-portal.org")
        assert prof.domain == "brand-new-fake-portal.org"
        assert prof.registrar == "GoDaddy.com, LLC"
        assert prof.domain_age_days == 12
        assert prof.is_newly_registered is True
        assert prof.risk_level == "critical"
        assert "clientTransferProhibited" in prof.status


def test_rdap_failure_fallback():
    DomainIntelService._cache.clear()

    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.get.side_effect = Exception("Network connection timeout")
        mock_client_cls.return_value = mock_client

        prof = DomainIntelService.lookup("unreachable-server.net")
        assert prof.domain == "unreachable-server.net"
        assert prof.risk_level == "unknown"
        assert prof.registrar == "Unresolved / Private Registrar"
        assert prof.is_newly_registered is False


def test_empty_or_invalid_domain():
    prof_empty = DomainIntelService.lookup("")
    assert prof_empty.risk_level == "unknown"

    prof_invalid = DomainIntelService.lookup("localhost")
    assert prof_invalid.risk_level == "unknown"
