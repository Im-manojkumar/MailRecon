import pytest
from app.enrichment.infra_tagger import InfrastructureTagger, InfrastructureType


def test_classify_private_lan():
    for ip in ["192.168.1.50", "10.0.0.1", "172.16.0.2", "127.0.0.1"]:
        tag = InfrastructureTagger.classify(ip)
        assert tag.infra_type == InfrastructureType.PRIVATE_LAN
        assert tag.risk_level == "info"
        assert not tag.is_anonymized


def test_classify_tor_exit():
    tor_ip = "185.220.101.5"
    tag = InfrastructureTagger.classify(tor_ip)
    assert tag.infra_type == InfrastructureType.TOR_EXIT
    assert tag.risk_level == "critical"
    assert tag.is_anonymized is True


def test_classify_vpn_proxy():
    tag = InfrastructureTagger.classify(
        "146.70.1.1",
        geoip_data={"isp": "Mullvad VPN AB", "asn": "AS12345", "org": "Mullvad"},
    )
    assert tag.infra_type == InfrastructureType.VPN_PROXY
    assert tag.risk_level == "high"
    assert tag.is_anonymized is True


def test_classify_cloud_hosting():
    tag_aws = InfrastructureTagger.classify(
        "54.240.0.1",
        geoip_data={"asn": "AS16509", "org": "Amazon.com, Inc.", "isp": "AWS EC2"},
    )
    assert tag_aws.infra_type == InfrastructureType.CLOUD_HOSTING
    assert tag_aws.risk_level == "medium"

    tag_hetzner = InfrastructureTagger.classify(
        "188.40.0.1",
        geoip_data={"asn": "AS24940", "org": "Hetzner Online GmbH", "isp": "Hetzner"},
    )
    assert tag_hetzner.infra_type == InfrastructureType.CLOUD_HOSTING


def test_classify_residential_broadband():
    tag = InfrastructureTagger.classify(
        "24.120.5.10",
        geoip_data={"isp": "Comcast Cable Communications, LLC", "asn": "AS7922", "org": "Comcast"},
    )
    assert tag.infra_type == InfrastructureType.RESIDENTIAL_BROADBAND
    assert tag.risk_level == "high"


def test_classify_enterprise_relay():
    tag = InfrastructureTagger.classify(
        "209.85.220.41",
        geoip_data={"asn": "AS15169", "org": "Google LLC", "isp": "Google LLC"},
    )
    assert tag.infra_type == InfrastructureType.ENTERPRISE_RELAY
    assert tag.risk_level == "low"


def test_classify_unknown():
    tag = InfrastructureTagger.classify("")
    assert tag.infra_type == InfrastructureType.UNKNOWN
    assert tag.risk_level == "info"
