import re
from typing import Any, Dict, List, Optional


def parse_authentication_results(
    auth_results_headers: List[str],
    received_spf_headers: List[str] | None = None
) -> Dict[str, Any]:
    """
    Parse RFC 8601 Authentication-Results and Received-SPF headers.
    
    IMPORTANT (Truthfulness Requirement):
    These headers are purely what the message claims or what an upstream MTA reported.
    They must be labeled with provenance='unverified_header_claim' and NOT accepted
    as absolute cryptographic proof until correlated with trustworthy Received hops.
    """
    res: Dict[str, Any] = {
        "authserv_id": None,
        "spf": {
            "result": None,
            "mailfrom": None,
            "details": None,
        },
        "dkim": {
            "result": None,
            "domain": None,
            "selector": None,
        },
        "dmarc": {
            "result": None,
            "from_domain": None,
        },
        "raw_headers": list(auth_results_headers or []),
        "provenance": "unverified_header_claim",
        "trust_warning": "Header claims are unverified text until cross-referenced with observed routing hops."
    }

    if received_spf_headers:
        res["raw_headers"].extend(received_spf_headers)

    if not auth_results_headers and not received_spf_headers:
        return res

    # Process Authentication-Results
    for header in auth_results_headers:
        # Example: mx.destination.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com
        parts = [p.strip() for p in header.split(";") if p.strip()]
        if not parts:
            continue

        if not res["authserv_id"]:
            # First token is the authserv-id (MTA domain or host)
            first_part = parts[0].split()[0] if parts[0] else None
            res["authserv_id"] = first_part

        for part in parts[1:]:
            part_lower = part.lower()

            # Parse SPF
            if part_lower.startswith("spf="):
                m = re.match(r"spf=([a-zA-Z0-9_-]+)", part, re.IGNORECASE)
                if m:
                    res["spf"]["result"] = m.group(1).lower()
                mailfrom_m = re.search(r"smtp\.mailfrom=([^\s;]+)", part, re.IGNORECASE)
                if mailfrom_m:
                    res["spf"]["mailfrom"] = mailfrom_m.group(1)
                res["spf"]["details"] = part

            # Parse DKIM
            elif part_lower.startswith("dkim="):
                m = re.match(r"dkim=([a-zA-Z0-9_-]+)", part, re.IGNORECASE)
                if m:
                    res["dkim"]["result"] = m.group(1).lower()
                domain_m = re.search(r"header\.[di]=([^\s;]+)", part, re.IGNORECASE)
                if domain_m:
                    res["dkim"]["domain"] = domain_m.group(1)
                selector_m = re.search(r"header\.s=([^\s;]+)", part, re.IGNORECASE)
                if selector_m:
                    res["dkim"]["selector"] = selector_m.group(1)

            # Parse DMARC
            elif part_lower.startswith("dmarc="):
                m = re.match(r"dmarc=([a-zA-Z0-9_-]+)", part, re.IGNORECASE)
                if m:
                    res["dmarc"]["result"] = m.group(1).lower()
                from_m = re.search(r"header\.from=([^\s;]+)", part, re.IGNORECASE)
                if from_m:
                    res["dmarc"]["from_domain"] = from_m.group(1)

    # Fallback to Received-SPF if spf not found in Authentication-Results
    if res["spf"]["result"] is None and received_spf_headers:
        for rspf in received_spf_headers:
            # e.g., "pass (mx.example.com: domain of test.com designates 1.2.3.4)"
            m = re.match(r"^([a-zA-Z0-9_-]+)", rspf.strip(), re.IGNORECASE)
            if m:
                res["spf"]["result"] = m.group(1).lower()
                res["spf"]["details"] = rspf.strip()
                break

    return res
