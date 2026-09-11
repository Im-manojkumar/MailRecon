"""
GeoIP Enrichment Provider for MailRecon AI.
Classifies RFC 1918 private / public IPs, maps public hops to geographic coordinates,
resolves ISPs, Organizations, and Autonomous System Numbers (ASN), with offline fallback.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
import hashlib
import ipaddress
import logging
import time
from typing import Any, Dict, Optional

import httpx

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
    isp: Optional[str] = None
    region: Optional[str] = None
    timezone: Optional[str] = None
    is_proxy: Optional[bool] = None
    is_hosting: Optional[bool] = None


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """Check if an IP string is an RFC 1918 private, loopback, link-local, or reserved address."""
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
        # (prefix, country, code, city, lat, lon, asn, org, isp)
        ("209.85.", "United States", "US", "Mountain View", 37.422, -122.084, "AS15169", "Google LLC", "Google"),
        ("40.", "United States", "US", "Redmond", 47.674, -122.121, "AS8075", "Microsoft Corporation", "Microsoft"),
        ("52.", "United States", "US", "Seattle", 47.606, -122.332, "AS16509", "Amazon.com, Inc.", "AWS"),
        ("185.", "Germany", "DE", "Frankfurt", 50.110, 8.682, "AS24940", "Hetzner Online GmbH", "Hetzner"),
        ("91.", "United Kingdom", "GB", "London", 51.507, -0.127, "AS1239", "Vodafone Group", "Vodafone"),
        ("194.", "France", "FR", "Paris", 48.856, 2.352, "AS15557", "Societe Francaise du Radiotelephone", "SFR"),
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
                isp="Local / Intranet",
                region="Local",
                timezone="UTC",
                is_proxy=False,
                is_hosting=False,
            )

        # 2. Match known prefixes
        for item in self.KNOWN_RANGES:
            prefix, country, code, city, lat, lon, asn, org, isp = item
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
                    isp=isp,
                    region="State/Region",
                    timezone="UTC",
                    is_proxy=False,
                    is_hosting="Hetzner" in org or "Amazon" in org,
                )

        # 3. Deterministic pseudo-location for unlisted public IPs
        h = int(hashlib.sha256(clean_ip.encode("utf-8")).hexdigest()[:8], 16)
        lat = round(20.0 + (h % 3500) / 100.0, 4)
        lon = round(-100.0 + (h % 14000) / 100.0, 4)

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
            isp="Public Telecom Provider",
            region="Observed Territory",
            timezone="UTC",
            is_proxy=False,
            is_hosting=False,
        )


class LiveGeoIPProvider(BaseGeoIPProvider):
    """
    Live GeoIP resolver utilizing real-time network intelligence (IP-API)
    with local memory caching and transparent fallback to MockGeoIPProvider.
    """
    def __init__(self, timeout: float = 3.0, fallback: Optional[BaseGeoIPProvider] = None):
        self.timeout = timeout
        self.fallback = fallback or MockGeoIPProvider()
        self._cache: Dict[str, tuple[float, GeoIPLocation]] = {}
        self._cache_ttl = 86400  # 24 hours cache

    def lookup(self, ip: str) -> GeoIPLocation:
        clean_ip = ip.strip()

        if is_private_or_reserved_ip(clean_ip):
            return self.fallback.lookup(clean_ip)

        now = time.time()
        if clean_ip in self._cache:
            ts, cached_loc = self._cache[clean_ip]
            if now - ts < self._cache_ttl:
                return cached_loc

        try:
            url = f"http://ip-api.com/json/{clean_ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query"
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        asn_val = data.get("as", "")
                        asn_clean = asn_val.split()[0] if asn_val else "UNKNOWN"
                        loc = GeoIPLocation(
                            ip=clean_ip,
                            country=data.get("country", "Unknown"),
                            country_code=data.get("countryCode", "XX"),
                            city=data.get("city"),
                            latitude=data.get("lat"),
                            longitude=data.get("lon"),
                            asn=asn_clean,
                            org=data.get("org") or data.get("isp"),
                            is_private=False,
                            isp=data.get("isp"),
                            region=data.get("regionName"),
                            timezone=data.get("timezone"),
                            is_proxy=data.get("proxy", False),
                            is_hosting=data.get("hosting", False),
                        )
                        self._cache[clean_ip] = (now, loc)
                        return loc
        except Exception as exc:
            logger.debug(f"Live GeoIP lookup failed for {clean_ip}: {exc}. Using deterministic fallback.")

        fallback_loc = self.fallback.lookup(clean_ip)
        self._cache[clean_ip] = (now, fallback_loc)
        return fallback_loc


_geoip_instance: Optional[BaseGeoIPProvider] = None


def get_geoip_provider() -> BaseGeoIPProvider:
    global _geoip_instance
    if _geoip_instance is None:
        _geoip_instance = LiveGeoIPProvider()
    return _geoip_instance
