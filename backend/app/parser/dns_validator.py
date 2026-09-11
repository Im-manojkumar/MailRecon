"""
Live DNS & Email Protocol Forensics Validator for MailRecon AI.
Performs active DNS queries for SPF records, DMARC policies, MX infrastructure,
calculates RFC 7489 identifier alignment, and inspects Message-ID syntax.
"""
from dataclasses import asdict, dataclass
import ipaddress
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import dns.exception
import dns.resolver

logger = logging.getLogger("mailrecon.parser.dns_validator")


@dataclass
class DmarcPolicyInfo:
    raw_record: Optional[str] = None
    policy: str = "none"  # "reject", "quarantine", "none", "absent"
    subdomain_policy: Optional[str] = None
    percentage: int = 100
    rua: Optional[str] = None
    is_enforced: bool = False  # True if reject or quarantine


@dataclass
class SpfRecordInfo:
    raw_record: Optional[str] = None
    mechanisms: List[str] = None
    default_policy: str = "neutral"  # "fail" (-all), "softfail" (~all), "neutral" (?all), "pass" (+all)
    is_ip_authorized: Optional[bool] = None
    matching_mechanism: Optional[str] = None


@dataclass
class MxRecordInfo:
    has_mx: bool = False
    servers: List[Dict[str, Any]] = None  # [{"preference": 10, "exchange": "mail.example.com"}]
    is_send_only: bool = False


@dataclass
class IdentifierAlignment:
    from_domain: str
    return_path_domain: Optional[str] = None
    dkim_domain: Optional[str] = None
    spf_alignment: str = "none"  # "strict", "relaxed", "fail"
    dkim_alignment: str = "none"  # "strict", "relaxed", "fail"
    dmarc_pass: bool = False


@dataclass
class LiveDnsValidationResult:
    domain: str
    dns_resolved: bool
    spf: SpfRecordInfo
    dmarc: DmarcPolicyInfo
    mx: MxRecordInfo
    alignment: IdentifierAlignment
    message_id_valid: bool
    anomalies: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "dns_resolved": self.dns_resolved,
            "spf": asdict(self.spf),
            "dmarc": asdict(self.dmarc),
            "mx": asdict(self.mx),
            "alignment": asdict(self.alignment),
            "message_id_valid": self.message_id_valid,
            "anomalies": self.anomalies,
        }


class DnsProtocolValidator:
    """
    Validates DNS authentication records and RFC 5322/7489 alignment.
    """
    _cache: Dict[str, tuple[float, LiveDnsValidationResult]] = {}
    _cache_ttl = 3600  # 1 hour

    @classmethod
    def _get_resolver(cls, timeout: float = 2.5) -> dns.resolver.Resolver:
        res = dns.resolver.Resolver()
        res.timeout = timeout
        res.lifetime = timeout
        return res

    @classmethod
    def get_base_domain(cls, domain: str) -> str:
        """Extract organizational/base domain (e.g. sub.example.com -> example.com)."""
        parts = domain.lower().strip().split(".")
        if len(parts) >= 2:
            # Simple 2-level TLD heuristic (e.g. co.uk, com.au)
            if len(parts) >= 3 and parts[-2] in ["co", "com", "org", "gov", "edu", "net"] and len(parts[-1]) == 2:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return domain.lower().strip()

    @classmethod
    def check_ip_in_spf(cls, ip_str: Optional[str], spf_mechanisms: List[str]) -> Tuple[Optional[bool], Optional[str]]:
        if not ip_str or not spf_mechanisms:
            return None, None
        try:
            target_ip = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return None, None

        for mech in spf_mechanisms:
            m_lower = mech.lower()
            if m_lower.startswith("ip4:"):
                cidr = m_lower[4:]
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if target_ip in net:
                        return True, mech
                except ValueError:
                    pass
            elif m_lower.startswith("ip6:"):
                cidr = m_lower[4:]
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if target_ip in net:
                        return True, mech
                except ValueError:
                    pass

        return False, None

    @classmethod
    def validate_domain(
        cls,
        from_domain: str,
        originating_ip: Optional[str] = None,
        return_path_domain: Optional[str] = None,
        dkim_domain: Optional[str] = None,
        message_id: Optional[str] = None,
    ) -> LiveDnsValidationResult:
        clean_domain = from_domain.lower().strip() if from_domain else ""
        if not clean_domain:
            return LiveDnsValidationResult(
                domain="",
                dns_resolved=False,
                spf=SpfRecordInfo(mechanisms=[]),
                dmarc=DmarcPolicyInfo(),
                mx=MxRecordInfo(servers=[]),
                alignment=IdentifierAlignment(from_domain=""),
                message_id_valid=True,
                anomalies=["Missing sender domain for DNS verification"],
            )

        cache_key = f"{clean_domain}|{originating_ip}|{return_path_domain}|{dkim_domain}"
        now = time.time()
        if cache_key in cls._cache:
            ts, cached_res = cls._cache[cache_key]
            if now - ts < cls._cache_ttl:
                return cached_res

        anomalies: List[str] = []
        resolver = cls._get_resolver()
        dns_resolved = False

        # 1. Query SPF Record (TXT on from_domain)
        spf_info = SpfRecordInfo(mechanisms=[])
        try:
            answers = resolver.resolve(clean_domain, "TXT")
            dns_resolved = True
            for rdata in answers:
                txt_string = "".join([part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part) for part in rdata.strings])
                if txt_string.lower().startswith("v=spf1"):
                    spf_info.raw_record = txt_string
                    parts = txt_string.split()
                    spf_info.mechanisms = parts[1:]
                    for p in parts:
                        if p.lower() == "-all":
                            spf_info.default_policy = "fail"
                        elif p.lower() == "~all":
                            spf_info.default_policy = "softfail"
                        elif p.lower() == "?all":
                            spf_info.default_policy = "neutral"
                        elif p.lower() == "+all":
                            spf_info.default_policy = "pass"
                            anomalies.append("Dangerous SPF policy: '+all' authorizes the entire Internet to send mail for this domain.")
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            anomalies.append(f"Domain '{clean_domain}' publishes no SPF TXT record.")
        except Exception as exc:
            logger.debug(f"SPF query failed for {clean_domain}: {exc}")

        # Check IP authorization in SPF
        if originating_ip and spf_info.mechanisms:
            is_auth, mech = cls.check_ip_in_spf(originating_ip, spf_info.mechanisms)
            spf_info.is_ip_authorized = is_auth
            spf_info.matching_mechanism = mech
            if is_auth is False and spf_info.default_policy in ["fail", "softfail"]:
                anomalies.append(
                    f"Originating IP '{originating_ip}' is not authorized in '{clean_domain}' SPF record (Policy: {spf_info.default_policy})."
                )

        # 2. Query DMARC Policy (TXT on _dmarc.domain)
        dmarc_info = DmarcPolicyInfo()
        dmarc_host = f"_dmarc.{clean_domain}"
        try:
            dmarc_answers = resolver.resolve(dmarc_host, "TXT")
            dns_resolved = True
            for rdata in dmarc_answers:
                txt_string = "".join([part.decode("utf-8", errors="ignore") if isinstance(part, bytes) else str(part) for part in rdata.strings])
                if txt_string.lower().startswith("v=dmarc1"):
                    dmarc_info.raw_record = txt_string
                    p_match = re.search(r"\bp=([a-zA-Z]+)", txt_string, re.IGNORECASE)
                    if p_match:
                        dmarc_info.policy = p_match.group(1).lower()
                    sp_match = re.search(r"\bsp=([a-zA-Z]+)", txt_string, re.IGNORECASE)
                    if sp_match:
                        dmarc_info.subdomain_policy = sp_match.group(1).lower()
                    pct_match = re.search(r"\bpct=(\d+)", txt_string, re.IGNORECASE)
                    if pct_match:
                        dmarc_info.percentage = int(pct_match.group(1))
                    rua_match = re.search(r"\brua=([^\s;]+)", txt_string, re.IGNORECASE)
                    if rua_match:
                        dmarc_info.rua = rua_match.group(1)

                    dmarc_info.is_enforced = dmarc_info.policy in ["reject", "quarantine"]
                    if dmarc_info.policy == "none":
                        anomalies.append(f"Weak DMARC policy: '{clean_domain}' publishes 'p=none' (monitoring only, no rejection).")
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            dmarc_info.policy = "absent"
            anomalies.append(f"Domain '{clean_domain}' has NO DMARC policy (_dmarc.{clean_domain} not published). Highly susceptible to spoofing.")
        except Exception as exc:
            logger.debug(f"DMARC query failed for {dmarc_host}: {exc}")

        # 3. Query MX Records
        mx_info = MxRecordInfo(servers=[])
        try:
            mx_answers = resolver.resolve(clean_domain, "MX")
            dns_resolved = True
            servers_list = []
            for rdata in mx_answers:
                servers_list.append({
                    "preference": rdata.preference,
                    "exchange": str(rdata.exchange).rstrip(".").lower(),
                })
            mx_info.has_mx = len(servers_list) > 0
            mx_info.servers = sorted(servers_list, key=lambda x: x["preference"])
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            mx_info.has_mx = False
            mx_info.is_send_only = True
            anomalies.append(f"Domain '{clean_domain}' has NO MX records configured. Likely a send-only burner domain.")
        except Exception as exc:
            logger.debug(f"MX query failed for {clean_domain}: {exc}")

        # 4. Compute SPF & DKIM Identifier Alignment
        base_from = cls.get_base_domain(clean_domain)
        
        # SPF Alignment (From domain vs Return-Path domain)
        clean_rp = return_path_domain.lower().strip() if return_path_domain else None
        spf_align = "fail"
        if clean_rp:
            if clean_rp == clean_domain:
                spf_align = "strict"
            elif cls.get_base_domain(clean_rp) == base_from:
                spf_align = "relaxed"
            else:
                spf_align = "fail"
                anomalies.append(f"SPF Identifier Unaligned: From ('{clean_domain}') differs from Return-Path ('{clean_rp}').")
        
        # DKIM Alignment (From domain vs DKIM d= domain)
        clean_dkim = dkim_domain.lower().strip() if dkim_domain else None
        dkim_align = "fail"
        if clean_dkim:
            if clean_dkim == clean_domain:
                dkim_align = "strict"
            elif cls.get_base_domain(clean_dkim) == base_from:
                dkim_align = "relaxed"
            else:
                dkim_align = "fail"
                anomalies.append(f"DKIM Identifier Unaligned: From ('{clean_domain}') differs from DKIM d= ('{clean_dkim}').")

        dmarc_pass = (spf_align in ["strict", "relaxed"]) or (dkim_align in ["strict", "relaxed"])

        alignment = IdentifierAlignment(
            from_domain=clean_domain,
            return_path_domain=clean_rp,
            dkim_domain=clean_dkim,
            spf_alignment=spf_align,
            dkim_alignment=dkim_align,
            dmarc_pass=dmarc_pass,
        )

        # 5. Message-ID Validation
        msg_id_valid = True
        if message_id:
            m = re.match(r"^<[^@]+@([^>]+)>$", message_id.strip())
            if not m:
                msg_id_valid = False
                anomalies.append(f"Malformed Message-ID header syntax: '{message_id}'.")
            else:
                msg_id_domain = m.group(1).lower()
                if cls.get_base_domain(msg_id_domain) != base_from:
                    anomalies.append(
                        f"Message-ID domain ('{msg_id_domain}') does not align with sender domain ('{clean_domain}')."
                    )

        result = LiveDnsValidationResult(
            domain=clean_domain,
            dns_resolved=dns_resolved,
            spf=spf_info,
            dmarc=dmarc_info,
            mx=mx_info,
            alignment=alignment,
            message_id_valid=msg_id_valid,
            anomalies=anomalies,
        )

        cls._cache[cache_key] = (now, result)
        return result
