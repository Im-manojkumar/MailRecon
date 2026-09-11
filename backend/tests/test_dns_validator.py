from unittest.mock import MagicMock, patch
import dns.resolver
import pytest

from app.parser.dns_validator import DnsProtocolValidator


def test_base_domain_extraction():
    assert DnsProtocolValidator.get_base_domain("example.com") == "example.com"
    assert DnsProtocolValidator.get_base_domain("sub.example.com") == "example.com"
    assert DnsProtocolValidator.get_base_domain("deep.sub.example.com") == "example.com"
    assert DnsProtocolValidator.get_base_domain("mail.company.co.uk") == "company.co.uk"
    assert DnsProtocolValidator.get_base_domain("invalid") == "invalid"


def test_check_ip_in_spf():
    mechanisms = ["ip4:192.0.2.0/24", "ip4:198.51.100.12", "ip6:2001:db8::/32", "-all"]
    
    # Matching IPv4 in subnet
    matched, mech = DnsProtocolValidator.check_ip_in_spf("192.0.2.45", mechanisms)
    assert matched is True
    assert mech == "ip4:192.0.2.0/24"

    # Matching exact IPv4
    matched, mech = DnsProtocolValidator.check_ip_in_spf("198.51.100.12", mechanisms)
    assert matched is True
    assert mech == "ip4:198.51.100.12"

    # Non-matching IPv4
    matched, mech = DnsProtocolValidator.check_ip_in_spf("203.0.113.1", mechanisms)
    assert matched is False
    assert mech is None

    # Matching IPv6
    matched, mech = DnsProtocolValidator.check_ip_in_spf("2001:db8:ffff::1", mechanisms)
    assert matched is True
    assert mech == "ip6:2001:db8::/32"

    # Invalid IP string
    matched, mech = DnsProtocolValidator.check_ip_in_spf("invalid-ip", mechanisms)
    assert matched is None


def test_alignment_and_message_id():
    DnsProtocolValidator._cache.clear()
    
    with patch.object(DnsProtocolValidator, "_get_resolver") as mock_res_factory:
        mock_resolver = MagicMock()
        mock_res_factory.return_value = mock_resolver
        
        # Simulate NXDOMAIN for all queries so we test purely local logic
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        # 1. Strict Alignment
        res_strict = DnsProtocolValidator.validate_domain(
            from_domain="example.com",
            return_path_domain="example.com",
            dkim_domain="example.com",
            message_id="<test12345@example.com>",
        )
        assert res_strict.alignment.spf_alignment == "strict"
        assert res_strict.alignment.dkim_alignment == "strict"
        assert res_strict.alignment.dmarc_pass is True
        assert res_strict.message_id_valid is True

        # 2. Relaxed Alignment
        res_relaxed = DnsProtocolValidator.validate_domain(
            from_domain="mail.example.com",
            return_path_domain="bounces.example.com",
            dkim_domain="example.com",
            message_id="<abc@example.com>",
        )
        assert res_relaxed.alignment.spf_alignment == "relaxed"
        assert res_relaxed.alignment.dkim_alignment == "relaxed"
        assert res_relaxed.alignment.dmarc_pass is True

        # 3. Unaligned / Spoofed
        res_fail = DnsProtocolValidator.validate_domain(
            from_domain="paypal.com",
            return_path_domain="attacker.com",
            dkim_domain="evil.net",
            message_id="malformed_message_id_without_brackets",
        )
        assert res_fail.alignment.spf_alignment == "fail"
        assert res_fail.alignment.dkim_alignment == "fail"
        assert res_fail.alignment.dmarc_pass is False
        assert res_fail.message_id_valid is False
        assert any("Malformed Message-ID" in a for a in res_fail.anomalies)


def test_mocked_dns_records_parsing():
    DnsProtocolValidator._cache.clear()
    
    with patch.object(DnsProtocolValidator, "_get_resolver") as mock_res_factory:
        mock_resolver = MagicMock()
        mock_res_factory.return_value = mock_resolver

        def side_effect(qname, rdtype):
            qstr = str(qname)
            if rdtype == "TXT" and qstr == "securedomain.com":
                txt_obj = MagicMock()
                txt_obj.strings = [b"v=spf1 ip4:192.0.2.0/24 -all"]
                return [txt_obj]
            elif rdtype == "TXT" and qstr == "_dmarc.securedomain.com":
                txt_obj = MagicMock()
                txt_obj.strings = [b"v=dmarc1; p=reject; pct=100; rua=mailto:dmarc@securedomain.com"]
                return [txt_obj]
            elif rdtype == "MX" and qstr == "securedomain.com":
                mx_obj = MagicMock()
                mx_obj.preference = 10
                mx_obj.exchange = "mail.securedomain.com."
                return [mx_obj]
            raise dns.resolver.NXDOMAIN()

        mock_resolver.resolve.side_effect = side_effect

        result = DnsProtocolValidator.validate_domain(
            from_domain="securedomain.com",
            originating_ip="192.0.2.55",
            return_path_domain="securedomain.com",
            dkim_domain="securedomain.com",
            message_id="<msg1@securedomain.com>",
        )

        assert result.dns_resolved is True
        assert result.spf.raw_record == "v=spf1 ip4:192.0.2.0/24 -all"
        assert result.spf.default_policy == "fail"
        assert result.spf.is_ip_authorized is True
        assert result.dmarc.policy == "reject"
        assert result.dmarc.is_enforced is True
        assert result.dmarc.percentage == 100
        assert result.mx.has_mx is True
        assert len(result.mx.servers) == 1
        assert result.mx.servers[0]["exchange"] == "mail.securedomain.com"
        assert result.alignment.dmarc_pass is True
