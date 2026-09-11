import pytest
from app.enrichment.route_analyzer import RouteAnalyzer


def test_origin_node_skips_private_hops():
    # Chain with private client hop, private gateway, and public ingress MTA
    chain = [
        {
            "hop": 1,
            "from": "user-pc.corp.internal",
            "by": "internal-gw.corp.internal",
            "ip": "192.168.1.105",
            "timestamp_iso": "2026-09-10T12:00:00+00:00",
        },
        {
            "hop": 2,
            "from": "internal-gw.corp.internal",
            "by": "outbound-dmz.corp.com",
            "ip": "10.10.0.1",
            "timestamp_iso": "2026-09-10T12:00:02+00:00",
        },
        {
            "hop": 3,
            "from": "outbound-dmz.corp.com",
            "by": "mail.destination.com",
            "ip": "185.220.101.5",
            "timestamp_iso": "2026-09-10T12:00:05+00:00",
        },
    ]

    result = RouteAnalyzer.analyze(chain)
    assert result.originating_node is not None
    assert result.originating_node["hop_number"] == 3
    assert result.originating_node["ip"] == "185.220.101.5"
    assert result.originating_node["is_originating"] is True
    # Since first public hop is hop 3, confidence is medium
    assert result.origin_confidence == "medium"
    assert result.originating_node["infra_tag"] is not None
    assert result.originating_node["infra_tag"]["infra_type"] == "TOR_EXIT"


def test_origin_node_direct_public_hop():
    # Chain starting directly from an external public IP
    chain = [
        {
            "hop": 1,
            "from": "mail-out.sender.com",
            "by": "mx1.recipient.com",
            "ip": "209.85.220.41",
            "timestamp_iso": "2026-09-10T12:00:00+00:00",
        },
        {
            "hop": 2,
            "from": "mx1.recipient.com",
            "by": "internal.recipient.com",
            "ip": "172.16.1.10",
            "timestamp_iso": "2026-09-10T12:00:03+00:00",
        },
    ]

    result = RouteAnalyzer.analyze(chain)
    assert result.originating_node is not None
    assert result.originating_node["hop_number"] == 1
    assert result.originating_node["ip"] == "209.85.220.41"
    assert result.origin_confidence == "high"


def test_origin_node_timing_anomaly_reduces_confidence():
    # Chain with negative transit delay (clock skew or forged hop)
    chain = [
        {
            "hop": 1,
            "from": "smtp1.source.com",
            "by": "relay1.source.com",
            "ip": "198.51.100.25",
            "timestamp_iso": "2026-09-10T12:00:00+00:00",
        },
        {
            "hop": 2,
            "from": "relay1.source.com",
            "by": "mx.target.com",
            "ip": "203.0.113.5",
            "timestamp_iso": "2026-09-10T11:58:00+00:00",  # -120 seconds!
        },
    ]

    result = RouteAnalyzer.analyze(chain)
    assert len(result.anomalies) > 0
    assert any("Negative transit delay" in a for a in result.anomalies)
    assert result.origin_confidence == "low"


def test_origin_node_purely_private_chain():
    chain = [
        {
            "hop": 1,
            "from": "host1",
            "by": "host2",
            "ip": "192.168.1.10",
            "timestamp_iso": "2026-09-10T12:00:00+00:00",
        },
        {
            "hop": 2,
            "from": "host2",
            "by": "host3",
            "ip": "10.0.0.5",
            "timestamp_iso": "2026-09-10T12:00:01+00:00",
        },
    ]

    result = RouteAnalyzer.analyze(chain)
    assert result.originating_node is not None
    assert result.origin_confidence == "low"


def test_origin_node_empty_chain():
    result = RouteAnalyzer.analyze([])
    assert result.originating_node is None
    assert result.origin_confidence == "inconclusive"
