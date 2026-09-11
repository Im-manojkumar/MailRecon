"""
Infrastructure Archetype Tagger for MailRecon AI.
Classifies sending and relay infrastructure into actionable threat categories:
TOR_EXIT, VPN_PROXY, CLOUD_HOSTING, RESIDENTIAL_BROADBAND, ENTERPRISE_RELAY, PRIVATE_LAN, UNKNOWN.
"""
from dataclasses import asdict, dataclass
import enum
import ipaddress
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("mailrecon.enrichment.infra_tagger")


class InfrastructureType(str, enum.Enum):
    TOR_EXIT = "TOR_EXIT"
    VPN_PROXY = "VPN_PROXY"
    CLOUD_HOSTING = "CLOUD_HOSTING"
    RESIDENTIAL_BROADBAND = "RESIDENTIAL_BROADBAND"
    ENTERPRISE_RELAY = "ENTERPRISE_RELAY"
    PRIVATE_LAN = "PRIVATE_LAN"
    UNKNOWN = "UNKNOWN"


@dataclass
class InfrastructureTag:
    infra_type: InfrastructureType
    label: str
    description: str
    risk_level: str  # "critical", "high", "medium", "low", "info"
    provider: Optional[str] = None
    is_anonymized: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "infra_type": self.infra_type.value,
            "label": self.label,
            "description": self.description,
            "risk_level": self.risk_level,
            "provider": self.provider,
            "is_anonymized": self.is_anonymized,
        }


# Known Cloud / VPS Datacenter ASNs and Org keywords
CLOUD_ASNS = {
    "AS16509": "Amazon Web Services (AWS)",
    "AS14618": "Amazon.com",
    "AS8075": "Microsoft Azure",
    "AS396982": "Google Cloud Platform",
    "AS14061": "DigitalOcean",
    "AS24940": "Hetzner Online",
    "AS16276": "OVHcloud",
    "AS63949": "Akamai / Linode",
    "AS31898": "Oracle Cloud",
    "AS20473": "Vultr / Choopa",
    "AS51167": "Contabo",
    "AS60068": "Datacamp Limited",
    "AS9009": "M247 Ltd",
    "AS46606": "Unified Layer",
    "AS212238": "Datacenter Lux",
}

CLOUD_KEYWORDS = [
    "amazon", "aws", "azure", "google cloud", "digitalocean", "hetzner",
    "ovh", "linode", "vultr", "contabo", "choopa", "m247", "datacamp",
    "hosting", "server", "vps", "cloud", "dedicated", "datacenter",
    "leaseweb", "colocrossing", "fastly", "cloudflare"
]

# Enterprise SaaS Mail Delivery Providers (Legitimate bulk/enterprise MTAs)
ENTERPRISE_MAIL_ASNS = {
    "AS15169": "Google Workspace / Gmail",
    "AS8075": "Microsoft 365 / Exchange Online",
    "AS33588": "Proofpoint",
    "AS34939": "Mimecast",
    "AS11377": "SendGrid / Twilio",
    "AS14782": "Mailgun",
}

# Major Residential / Consumer ISPs (High risk if originating direct SMTP)
RESIDENTIAL_KEYWORDS = [
    "comcast", "charter", "spectrum", "verizon", "at&t", "cox", "centurylink",
    "telekom", "vodafone", "orange", "telefonica", "virgin media", "bt group",
    "broadband", "cable", "dsl", "dialup", "dynamic", "pool", "residential",
    "airtel", "jio", "bsnl", "t-mobile", "sprint", "bell canada", "rogers"
]

# Commercial VPN / Proxy Providers
VPN_PROXY_KEYWORDS = [
    "nordvpn", "mullvad", "protonvpn", "expressvpn", "surfshark",
    "private internet access", "pia", "cyberghost", "windscribe",
    "torguard", "purevpn", "ivpn", "vpn", "proxy", "exit", "anonymizer"
]

# Sample active Tor exit nodes (and prefix triggers for offline/deterministic test coverage)
KNOWN_TOR_IPS = {
    "185.220.101.", "185.220.102.", "185.220.103.", "171.25.193.", "51.15.43."
}


class InfrastructureTagger:
    """
    Analyzes network telemetry, ASN, reverse DNS, and GeoIP signals
    to categorize mail server infrastructure.
    """

    @classmethod
    def classify(
        cls,
        ip: str,
        geoip_data: Optional[Dict[str, Any]] = None,
        reverse_dns: Optional[str] = None,
    ) -> InfrastructureTag:
        clean_ip = ip.strip() if ip else ""
        if not clean_ip:
            return InfrastructureTag(
                infra_type=InfrastructureType.UNKNOWN,
                label="Unknown Infrastructure",
                description="No IP address available to determine network infrastructure.",
                risk_level="info",
            )

        # 1. Private RFC 1918 / Loopback
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return InfrastructureTag(
                    infra_type=InfrastructureType.PRIVATE_LAN,
                    label="Internal Network (RFC 1918)",
                    description=f"Internal private IP ({clean_ip}) within non-routable address space.",
                    risk_level="info",
                    provider="Intranet / Local Area Network",
                    is_anonymized=False,
                )
        except ValueError:
            pass

        # 2. Tor Exit Node
        for prefix in KNOWN_TOR_IPS:
            if clean_ip.startswith(prefix):
                return InfrastructureTag(
                    infra_type=InfrastructureType.TOR_EXIT,
                    label="TOR Anonymization Exit Node",
                    description="Email relayed through a known Onion Router (TOR) exit node. Legitimate enterprise email almost never originates from TOR.",
                    risk_level="critical",
                    provider="The Tor Project",
                    is_anonymized=True,
                )

        g = geoip_data or {}
        asn = (g.get("asn") or "").strip().upper()
        org = (g.get("org") or "").lower()
        isp = (g.get("isp") or "").lower()
        is_proxy = bool(g.get("is_proxy"))
        is_hosting = bool(g.get("is_hosting"))
        rdns = (reverse_dns or "").lower()
        combined_text = f"{asn} {org} {isp} {rdns}"

        # 3. Commercial VPN or Anonymizing Proxy
        if is_proxy or any(k in combined_text for k in VPN_PROXY_KEYWORDS):
            matched_prov = next((k.title() for k in VPN_PROXY_KEYWORDS if k in combined_text), "Commercial VPN / Proxy")
            return InfrastructureTag(
                infra_type=InfrastructureType.VPN_PROXY,
                label=f"VPN / Proxy ({matched_prov})",
                description=f"Transmission passed through an anonymizing VPN or proxy gateway ({matched_prov}). Hides true geographic origin.",
                risk_level="high",
                provider=matched_prov,
                is_anonymized=True,
            )

        # 4. Enterprise Cloud Email Services (Google Workspace / M365)
        if asn in ENTERPRISE_MAIL_ASNS:
            ent_name = ENTERPRISE_MAIL_ASNS[asn]
            return InfrastructureTag(
                infra_type=InfrastructureType.ENTERPRISE_RELAY,
                label=f"Enterprise Mail ({ent_name})",
                description=f"Authorized enterprise mail relay infrastructure hosted on {ent_name}.",
                risk_level="low",
                provider=ent_name,
                is_anonymized=False,
            )

        # 5. Cloud Hosting / VPS / Datacenter
        if is_hosting or asn in CLOUD_ASNS or any(k in combined_text for k in CLOUD_KEYWORDS):
            cloud_name = CLOUD_ASNS.get(asn)
            if not cloud_name:
                cloud_name = next((k.title() for k in CLOUD_KEYWORDS if k in combined_text), "Cloud VPS Provider")
            return InfrastructureTag(
                infra_type=InfrastructureType.CLOUD_HOSTING,
                label=f"Cloud / VPS Hosting ({cloud_name})",
                description=f"Transmitted from a commercial datacenter or cloud VPS ({cloud_name}). Common infrastructure for disposable phishing relays and bulletproof servers.",
                risk_level="medium",
                provider=cloud_name,
                is_anonymized=False,
            )

        # 6. Residential Broadband / Consumer ISP
        if any(k in combined_text for k in RESIDENTIAL_KEYWORDS):
            isp_name = next((k.title() for k in RESIDENTIAL_KEYWORDS if k in combined_text), "Consumer ISP")
            return InfrastructureTag(
                infra_type=InfrastructureType.RESIDENTIAL_BROADBAND,
                label=f"Residential ISP ({isp_name})",
                description=f"Originated directly from consumer broadband or residential cable/DSL ({isp_name}). High likelihood of compromised workstation, malware bot, or misconfigured open proxy.",
                risk_level="high",
                provider=isp_name,
                is_anonymized=False,
            )

        # 7. Default Public Network
        return InfrastructureTag(
            infra_type=InfrastructureType.UNKNOWN,
            label="Public Internet Relay",
            description=f"Standard commercial telecom gateway ({g.get('org') or g.get('isp') or 'Public Gateway'}).",
            risk_level="low",
            provider=g.get("org") or g.get("isp"),
            is_anonymized=False,
        )
