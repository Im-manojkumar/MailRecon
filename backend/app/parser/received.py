import re
from typing import Any, Dict, List


def parse_received_headers(received_headers: List[str]) -> List[Dict[str, Any]]:
    """
    Parse Received headers and arrange them in chronological order (hop 1 to N).
    
    RFC 5322 prepends Received headers at each relay, so the last header in the raw list
    corresponds to the earliest observed hop, while the first header was added by the final MX.
    Reversing the list yields chronological path reconstruction.
    """
    if not received_headers:
        return []

    # Reverse to chronological order (originating hop first, recipient final MX last)
    chronological_headers = list(reversed(received_headers))
    hops: List[Dict[str, Any]] = []

    for idx, raw in enumerate(chronological_headers, start=1):
        hop_info: Dict[str, Any] = {
            "hop_number": idx,
            "from_claimed": None,
            "by_node": None,
            "ip": None,
            "protocol": None,
            "is_tls": False,
            "timestamp": None,
            "raw": " ".join(raw.split()),
        }

        # Extract timestamp after semicolon
        if ";" in raw:
            parts = raw.rsplit(";", 1)
            hop_info["timestamp"] = parts[1].strip()
            routing_part = parts[0]
        else:
            routing_part = raw

        # Extract from clause: "from <host>"
        from_match = re.search(r"\bfrom\s+([^\s();]+)", routing_part, re.IGNORECASE)
        if from_match:
            hop_info["from_claimed"] = from_match.group(1).strip()

        # Extract by clause: "by <host>"
        by_match = re.search(r"\bby\s+([^\s();]+)", routing_part, re.IGNORECASE)
        if by_match:
            hop_info["by_node"] = by_match.group(1).strip()

        # Extract IP address: look for IP in square brackets [1.2.3.4] or parenthesis
        ip_match = re.search(r"\[([0-9a-fA-F:.]+)\]", routing_part)
        if not ip_match:
            # Try plain IP preceded by unknown/helo
            ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", routing_part)

        if ip_match:
            hop_info["ip"] = ip_match.group(1).strip()

        # Extract protocol: "with <proto>"
        proto_match = re.search(r"\bwith\s+([a-zA-Z0-9_-]+)", routing_part, re.IGNORECASE)
        if proto_match:
            proto = proto_match.group(1).upper()
            hop_info["protocol"] = proto
            # Check if TLS was used (e.g. ESMTPS, ESMTPA, TLS, etc.)
            if "TLS" in proto or proto.endswith("S"):
                hop_info["is_tls"] = True

        hops.append(hop_info)

    return hops
