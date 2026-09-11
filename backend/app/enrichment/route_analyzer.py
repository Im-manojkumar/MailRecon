"""
Route Analyzer for MailRecon AI.
Analyzes chronological Received headers, calculates inter-hop transit delays,
enriches with GeoIP metadata, classifies infrastructure, and isolates originating node.
"""
from dataclasses import asdict, dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
import logging
from typing import Any, Dict, List, Optional

from app.enrichment.geoip import GeoIPLocation, get_geoip_provider, is_private_or_reserved_ip
from app.enrichment.infra_tagger import InfrastructureTagger

logger = logging.getLogger("mailrecon.enrichment.route")



@dataclass
class EnrichedHop:
    hop_number: int
    from_host: Optional[str]
    by_host: Optional[str]
    ip: Optional[str]
    timestamp_iso: Optional[str]
    delay_seconds: float
    geoip: Optional[Dict[str, Any]]
    infra_tag: Optional[Dict[str, Any]] = None
    is_originating: bool = False


@dataclass
class RouteAnalysisResult:
    hops: List[EnrichedHop]
    total_transit_seconds: float
    anomalies: List[str]
    originating_node: Optional[Dict[str, Any]] = None
    origin_confidence: str = "inconclusive"  # "high", "medium", "low", "inconclusive"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hops": [asdict(h) for h in self.hops],
            "total_transit_seconds": self.total_transit_seconds,
            "anomalies": self.anomalies,
            "originating_node": self.originating_node,
            "origin_confidence": self.origin_confidence,
        }


class RouteAnalyzer:
    """
    Computes chronological route progression, transit delays, routing anomalies,
    classifies infrastructure, and isolates the earliest reliable originating ingress node.
    """

    @classmethod
    def _parse_timestamp(cls, ts_str: Optional[str]) -> Optional[datetime]:
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            try:
                return parsedate_to_datetime(ts_str)
            except Exception:
                return None

    @classmethod
    def _identify_originating_node(
        cls, hops: List[EnrichedHop], anomalies: List[str]
    ) -> tuple[Optional[EnrichedHop], str]:
        """
        Pinpoints the earliest trustworthy public ingress node in the transmission chain.
        Filters out internal LAN/RFC1918 hops and forged client claims.
        """
        if not hops:
            return None, "inconclusive"

        # 1. Look for the earliest hop with a routable public IP
        first_public_hop: Optional[EnrichedHop] = None
        for hop in hops:
            if hop.ip and not is_private_or_reserved_ip(hop.ip):
                first_public_hop = hop
                break

        if not first_public_hop:
            # All hops were private or missing IPs (purely internal transmission)
            if hops[0].ip:
                return hops[0], "low"
            return None, "inconclusive"

        # Determine confidence based on position and anomalies
        has_negative_delay = any("Negative transit delay" in a for a in anomalies)
        
        if first_public_hop.hop_number == 1 and not has_negative_delay:
            # First hop is public and chronological order is sound
            confidence = "high"
        elif first_public_hop.hop_number > 1 and not has_negative_delay:
            # Internal MUA/submission relayed out to first public gateway
            confidence = "medium"
        else:
            # Chain contains timing anomalies or forged records
            confidence = "low"

        first_public_hop.is_originating = True
        return first_public_hop, confidence

    @classmethod
    def analyze(cls, received_chain: List[Dict[str, Any]]) -> RouteAnalysisResult:
        if not received_chain:
            return RouteAnalysisResult(
                hops=[],
                total_transit_seconds=0.0,
                anomalies=[],
                originating_node=None,
                origin_confidence="inconclusive",
            )

        geoip_provider = get_geoip_provider()
        enriched_hops: List[EnrichedHop] = []
        anomalies: List[str] = []

        prev_dt: Optional[datetime] = None
        first_dt: Optional[datetime] = None
        last_dt: Optional[datetime] = None

        for idx, raw_hop in enumerate(received_chain):
            hop_num = idx + 1
            ip_str = raw_hop.get("ip")
            from_host = raw_hop.get("from_host") or raw_hop.get("from")
            by_host = raw_hop.get("by_host") or raw_hop.get("by")
            ts_str = raw_hop.get("timestamp_iso") or raw_hop.get("timestamp")

            curr_dt = cls._parse_timestamp(ts_str)
            if curr_dt and first_dt is None:
                first_dt = curr_dt
            if curr_dt:
                last_dt = curr_dt

            delay_sec = 0.0
            if prev_dt and curr_dt:
                delta = (curr_dt - prev_dt).total_seconds()
                delay_sec = round(delta, 1)

                if delay_sec < -15.0:
                    anomalies.append(
                        f"Hop {hop_num} ({by_host or 'MTA'}): Negative transit delay of "
                        f"{abs(delay_sec):.0f}s detected. Potential clock skew or forged Received header."
                    )
                elif delay_sec > 3600.0:
                    hours = delay_sec / 3600.0
                    anomalies.append(
                        f"Hop {hop_num} ({by_host or 'MTA'}): Excessive transit delay of "
                        f"{hours:.1f} hours detected."
                    )

            if curr_dt:
                prev_dt = curr_dt

            geoip_data = None
            infra_data = None
            if ip_str:
                loc = geoip_provider.lookup(ip_str)
                geoip_data = asdict(loc)
                tag = InfrastructureTagger.classify(ip_str, geoip_data, from_host)
                infra_data = tag.to_dict()

            enriched_hops.append(
                EnrichedHop(
                    hop_number=hop_num,
                    from_host=from_host,
                    by_host=by_host,
                    ip=ip_str,
                    timestamp_iso=curr_dt.isoformat() if curr_dt else None,
                    delay_seconds=max(0.0, delay_sec),
                    geoip=geoip_data,
                    infra_tag=infra_data,
                    is_originating=False,
                )
            )

        total_transit = 0.0
        if first_dt and last_dt:
            total_transit = max(0.0, round((last_dt - first_dt).total_seconds(), 1))

        # Identify the true earliest public entry node
        orig_node, confidence = cls._identify_originating_node(enriched_hops, anomalies)
        orig_dict = asdict(orig_node) if orig_node else None

        return RouteAnalysisResult(
            hops=enriched_hops,
            total_transit_seconds=total_transit,
            anomalies=anomalies,
            originating_node=orig_dict,
            origin_confidence=confidence,
        )

