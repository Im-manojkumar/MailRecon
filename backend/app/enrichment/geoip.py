"""
GeoIP Enrichment Provider for MailRecon AI.
Classifies RFC 1918 private / public IPs and maps public hops to geographic coordinates and ASNs.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
import hashlib
import ipaddress
import logging
from typing import Optional

logger = logging.getLogger("mailrecon.enrichment.geoip")


@dataclass
class GeoIPLocation:
    ip: str
    country: str
    country_code: str
    city: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    asn: Optional[str]
    org: Optional[str]
    is_private: bool


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """Check if an IP string is an RFC 1918 private, loopback, or link-local address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved
    except ValueError:
        return False


class BaseGeoIPProvider(ABC):
    @abstractmethod
    def lookup(self, ip: str) -> GeoIPLocation:
        """Resolve an IP address to geographic and network metadata."""
        pass


class MockGeoIPProvider(BaseGeoIPProvider):
    """
    Deterministic GeoIP resolver for offline testing, hermetic builds, and local development.
    Maps private networks cleanly and provides stable geographic coordinates for public addresses.
    """
    KNOWN_RANGES = [
        # (prefix, country, code, city, lat, lon, asn, org)
        ("209.85.", "United States", "US", "Mountain View", 37.422, -122.084, "AS15169", "Google LLC"),
        ("40.", "United States", "US", "Redmond", 47.674, -122.121, "AS8075", "Microsoft Corporation"),
        ("52.", "United States", "US", "Seattle", 47.606, -122.332, "AS16509", "Amazon.com, Inc."),
        ("185.", "Germany", "DE", "Frankfurt", 50.110, 8.682, "AS24940", "Hetzner Online GmbH"),
        ("91.", "United Kingdom", "GB", "London", 51.507, -0.127, "AS1239", "Vodafone Group"),
        ("194.", "France", "FR", "Paris", 48.856, 2.352, "AS15557", "Societe Francaise du Radiotelephone"),
    ]

    def lookup(self, ip: str) -> GeoIPLocation:
        clean_ip = ip.strip()

        # 1. Private / Internal IPs
        if is_private_or_reserved_ip(clean_ip):
            return GeoIPLocation(
                ip=clean_ip,
                country="Internal / Private Network",
                country_code="LAN",
                city="Local Network",
                latitude=None,
                longitude=None,
                asn="RFC1918",
                org="Private Address Space",
                is_private=True,
            )

        # 2. Match known prefixes
        for prefix, country, code, city, lat, lon, asn, org in self.KNOWN_RANGES:
            if clean_ip.startswith(prefix):
                return GeoIPLocation(
                    ip=clean_ip,
                    country=country,
                    country_code=code,
                    city=city,
                    latitude=lat,
                    longitude=lon,
                    asn=asn,
                    org=org,
                    is_private=False,
                )

        # 3. Deterministic pseudo-location for unlisted public IPs
        # Derive stable lat/lon from IP hash to provide consistent map points in offline dev
        h = int(hashlib.sha256(clean_ip.encode("utf-8")).hexdigest()[:8], 16)
        lat = round(20.0 + (h % 3500) / 100.0, 4)   # ~20.0 to 55.0 N
        lon = round(-100.0 + (h % 14000) / 100.0, 4) # ~ -100.0 to 40.0

        return GeoIPLocation(
            ip=clean_ip,
            country="External Public Network",
            country_code="PUB",
            city="Observed Hop",
            latitude=lat,
            longitude=lon,
            asn=f"AS{10000 + (h % 50000)}",
            org="Public Gateway",
            is_private=False,
        )


_geoip_instance: Optional[BaseGeoIPProvider] = None


def get_geoip_provider() -> BaseGeoIPProvider:
    global _geoip_instance
    if _geoip_instance is None:
        _geoip_instance = MockGeoIPProvider()
    return _geoip_instance
