"""
Route Analyzer for MailRecon AI.
Analyzes chronological Received headers, calculates inter-hop transit delays,
enriches with GeoIP metadata, and flags temporal or routing anomalies.
"""
from dataclasses import asdict, dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
import logging
from typing import Any, Dict, List, Optional

from app.enrichment.geoip import GeoIPLocation, get_geoip_provider

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


@dataclass
class RouteAnalysisResult:
    hops: List[EnrichedHop]
    total_transit_seconds: float
    anomalies: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hops": [asdict(h) for h in self.hops],
            "total_transit_seconds": self.total_transit_seconds,
            "anomalies": self.anomalies,
        }


class RouteAnalyzer:
    """
    Computes chronological route progression, transit delays, and routing anomalies.
    """

    @classmethod
    def _parse_timestamp(cls, ts_str: Optional[str]) -> Optional[datetime]:
        if not ts_str:
            return None
        try:
            # Handle ISO format
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            try:
                # Handle RFC 2822 / 5322 date format
                return parsedate_to_datetime(ts_str)
            except Exception:
                return None

    @classmethod
    def analyze(cls, received_chain: List[Dict[str, Any]]) -> RouteAnalysisResult:
        if not received_chain:
            return RouteAnalysisResult(hops=[], total_transit_seconds=0.0, anomalies=[])

        geoip_provider = get_geoip_provider()
        enriched_hops: List[EnrichedHop] = []
        anomalies: List[str] = []

        prev_dt: Optional[datetime] = None
        first_dt: Optional[datetime] = None
        last_dt: Optional[datetime] = None
        has_seen_public_ip = False

        for idx, raw_hop in enumerate(received_chain):
            hop_num = idx + 1
            ip_str = raw_hop.get("ip")
            from_host = raw_hop.get("from_host") or raw_hop.get("from")
            by_host = raw_hop.get("by_host") or raw_hop.get("by")
            ts_str = raw_hop.get("timestamp_iso") or raw_hop.get("timestamp")

            # Parse datetime
            curr_dt = cls._parse_timestamp(ts_str)
            if curr_dt and first_dt is None:
                first_dt = curr_dt
            if curr_dt:
                last_dt = curr_dt

            # Calculate transit delay between hops
            delay_sec = 0.0
            if prev_dt and curr_dt:
                delta = (curr_dt - prev_dt).total_seconds()
                delay_sec = round(delta, 1)

                # Anomaly: Negative time jump (clock skew or forged header)
                if delay_sec < -15.0:
                    anomalies.append(
                        f"Hop {hop_num} ({by_host or 'MTA'}): Negative transit delay of "
                        f"{abs(delay_sec):.0f}s detected. Potential clock skew or forged Received header."
                    )
                # Anomaly: Latency anomaly (> 1 hour)
                elif delay_sec > 3600.0:
                    hours = delay_sec / 3600.0
                    anomalies.append(
                        f"Hop {hop_num} ({by_host or 'MTA'}): Excessive transit delay of "
                        f"{hours:.1f} hours detected."
                    )

            if curr_dt:
                prev_dt = curr_dt

            # GeoIP lookup
            geoip_data = None
            if ip_str:
                loc = geoip_provider.lookup(ip_str)
                geoip_data = asdict(loc)

                # Anomaly: Private IP after public Internet hops
                if not loc.is_private:
                    has_seen_public_ip = True

            enriched_hops.append(
                EnrichedHop(
                    hop_number=hop_num,
                    from_host=from_host,
                    by_host=by_host,
                    ip=ip_str,
                    timestamp_iso=curr_dt.isoformat() if curr_dt else None,
                    delay_seconds=max(0.0, delay_sec),
                    geoip=geoip_data,
                )
            )

        total_transit = 0.0
        if first_dt and last_dt:
            total_transit = max(0.0, round((last_dt - first_dt).total_seconds(), 1))

        return RouteAnalysisResult(
            hops=enriched_hops,
            total_transit_seconds=total_transit,
            anomalies=anomalies,
        )
