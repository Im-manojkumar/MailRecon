"""
Indicator Graph Builder for MailRecon AI.
Constructs a Cytoscape.js compatible network graph connecting email identity,
infrastructure, payloads, and findings with threat attribution.
"""
from dataclasses import dataclass
import email.utils
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from app.detectors.base import FindingData
from app.models.finding import SeverityLevel
from app.models.indicator import Indicator, IndicatorKind
from app.parser.email_parser import ParsedEmailResult
from app.parser.urls import defang_url
from app.schemas.indicator import GraphEdge, GraphNode, IndicatorGraphResponse


def get_header(headers: Dict[str, Any], *candidates: str) -> Optional[str]:
    """Retrieve header value by checking multiple key candidates, lowercase, and underscores."""
    if not headers:
        return None
    for cand in candidates:
        if cand in headers and headers[cand]:
            return str(headers[cand])
        lowered = cand.lower()
        if lowered in headers and headers[lowered]:
            return str(headers[lowered])
        underscored = lowered.replace("-", "_")
        if underscored in headers and headers[underscored]:
            return str(headers[underscored])
        hyphenated = lowered.replace("_", "-")
        if hyphenated in headers and headers[hyphenated]:
            return str(headers[hyphenated])
        all_hdrs = headers.get("all_headers")
        if isinstance(all_hdrs, dict):
            if lowered in all_hdrs and all_hdrs[lowered]:
                val = all_hdrs[lowered]
                return str(val[0] if isinstance(val, list) else val)
    return None


def parse_email_address_and_domain(header_value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not header_value:
        return None, None
    _, addr = email.utils.parseaddr(header_value)
    if not addr or "@" not in addr:
        return None, None
    clean_addr = addr.lower().strip()
    domain = clean_addr.split("@", 1)[1]
    return clean_addr, domain


class IndicatorGraphBuilder:
    """
    Builds Cytoscape.js graph structure and extracts database indicator records.
    """

    @classmethod
    def extract_indicators(
        cls,
        case_id: uuid.UUID,
        parsed: ParsedEmailResult,
        qr_codes: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Indicator]:
        """Extract all unique indicators from parsed email for database persistence."""
        seen: Set[Tuple[IndicatorKind, str]] = set()
        indicators: List[Indicator] = []

        def add_ind(kind: IndicatorKind, val: Optional[str], ctx: str):
            if not val:
                return
            clean_val = val.strip()
            if not clean_val:
                return
            key = (kind, clean_val.lower() if kind != IndicatorKind.hash else clean_val)
            if key not in seen:
                seen.add(key)
                indicators.append(
                    Indicator(
                        case_id=case_id,
                        kind=kind,
                        value=clean_val,
                        context=ctx,
                    )
                )

        # 1. Emails & Domains from Headers
        from_email, from_domain = parse_email_address_and_domain(get_header(parsed.headers, "from", "From"))
        add_ind(IndicatorKind.email, from_email, "Header: From")
        add_ind(IndicatorKind.domain, from_domain, "Sender Domain")

        to_email, to_domain = parse_email_address_and_domain(get_header(parsed.headers, "to", "To"))
        add_ind(IndicatorKind.email, to_email, "Header: To")
        add_ind(IndicatorKind.domain, to_domain, "Recipient Domain")

        reply_email, reply_domain = parse_email_address_and_domain(get_header(parsed.headers, "reply-to", "reply_to", "Reply-To"))
        if reply_email and reply_email != from_email:
            add_ind(IndicatorKind.email, reply_email, "Header: Reply-To")
            add_ind(IndicatorKind.domain, reply_domain, "Reply-To Domain")

        # 2. Routing Hop IPs
        for hop in parsed.received_chain:
            ip = hop.get("ip")
            if ip:
                add_ind(IndicatorKind.ip, ip, f"Received Hop {hop.get('hop', '')}")

        # 3. URLs & URL Domains
        for u in parsed.urls:
            raw_url = u.get("url")
            domain = u.get("domain")
            add_ind(IndicatorKind.url, raw_url, "Extracted Body URL")
            add_ind(IndicatorKind.domain, domain, "URL Target Domain")

        # 4. Attachment Hashes
        for att in parsed.attachments:
            if att.sha256:
                add_ind(IndicatorKind.hash, att.sha256, f"Attachment: {att.filename}")

        # 5. QR Code URLs
        if qr_codes:
            for qr in qr_codes:
                text = qr.get("decoded_text")
                if text:
                    kind = IndicatorKind.qr_url if qr.get("is_url") else IndicatorKind.url
                    add_ind(kind, text, f"QR Matrix: {qr.get('attachment_name')}")

        return indicators

    @classmethod
    def build_graph(
        cls,
        case_id: uuid.UUID,
        parsed: ParsedEmailResult,
        findings: List[FindingData],
        qr_codes: Optional[List[Dict[str, Any]]] = None,
    ) -> IndicatorGraphResponse:
        nodes: Dict[str, GraphNode] = {}
        edges: List[GraphEdge] = []
        edge_ids: Set[str] = set()

        # Identify malicious/suspicious tokens from findings
        flagged_entities: Dict[str, str] = {}  # entity_str -> risk_level
        highest_severity = "neutral"

        for f in findings:
            sev_level = "malicious" if f.severity in [SeverityLevel.critical, SeverityLevel.high] else "suspicious"
            if sev_level == "malicious":
                highest_severity = "malicious"
            elif highest_severity != "malicious":
                highest_severity = "suspicious"

            # Check evidence references for flagged entities
            ev_ref = (f.evidence_ref or "").lower()
            for token in re.findall(r"[\w.-]+@[\w.-]+\.\w+|\b(?:\d{1,3}\.){3}\d{1,3}\b|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", f.detail):
                flagged_entities[token.lower()] = sev_level

        def get_risk(val: str, default_risk: str = "neutral") -> str:
            val_clean = val.lower()
            for entity, risk in flagged_entities.items():
                if entity in val_clean:
                    return risk
            return default_risk

        def add_node(node_id: str, kind: str, value: str, label: str, risk: str = "neutral", meta: dict = None):
            if node_id not in nodes:
                actual_risk = get_risk(value, risk)
                nodes[node_id] = GraphNode(
                    id=node_id,
                    kind=kind,
                    value=value,
                    label=label,
                    risk_level=actual_risk,
                    metadata=meta or {},
                )

        def add_edge(src: str, tgt: str, rel: str, label: Optional[str] = None):
            edge_id = f"{src}->{tgt}:{rel}"
            if edge_id not in edge_ids:
                edge_ids.add(edge_id)
                edges.append(
                    GraphEdge(
                        id=edge_id,
                        source=src,
                        target=tgt,
                        relationship=rel,
                        label=label or rel.replace("_", " ").title(),
                    )
                )

        # 1. Root Case Node
        root_id = f"case:{case_id}"
        subject_preview = (get_header(parsed.headers, "subject", "Subject") or "(No Subject)")[:35]
        add_node(root_id, "case", str(case_id), f"Email: {subject_preview}", risk=highest_severity)

        # 2. Sender and Recipient Nodes
        from_email, from_domain = parse_email_address_and_domain(get_header(parsed.headers, "from", "From"))
        if from_email:
            sender_id = f"email:{from_email}"
            add_node(sender_id, "email", from_email, from_email)
            add_edge(root_id, sender_id, "sent_by", "Sent By")

            if from_domain:
                s_dom_id = f"domain:{from_domain}"
                add_node(s_dom_id, "domain", from_domain, from_domain)
                add_edge(sender_id, s_dom_id, "from_domain", "Domain")

        to_email, to_domain = parse_email_address_and_domain(get_header(parsed.headers, "to", "To"))
        if to_email:
            recip_id = f"email:{to_email}"
            add_node(recip_id, "email", to_email, to_email)
            add_edge(root_id, recip_id, "sent_to", "Sent To")

        reply_email, reply_domain = parse_email_address_and_domain(get_header(parsed.headers, "reply-to", "reply_to", "Reply-To"))
        if reply_email and reply_email != from_email:
            reply_id = f"email:{reply_email}"
            add_node(reply_id, "email", reply_email, f"Reply: {reply_email}", risk="suspicious")
            add_edge(root_id, reply_id, "reply_to", "Reply-To")
            if reply_domain:
                r_dom_id = f"domain:{reply_domain}"
                add_node(r_dom_id, "domain", reply_domain, reply_domain, risk="suspicious")
                add_edge(reply_id, r_dom_id, "reply_domain", "Reply Domain")

        # 3. Routing Hops
        prev_hop_id = root_id
        for hop in parsed.received_chain:
            hop_ip = hop.get("ip")
            if hop_ip:
                ip_id = f"ip:{hop_ip}"
                add_node(ip_id, "ip", hop_ip, hop_ip)
                add_edge(prev_hop_id, ip_id, "relayed_by", f"Hop {hop.get('hop', '')}")
                prev_hop_id = ip_id

        # 4. URLs
        for idx, u in enumerate(parsed.urls[:12]):
            raw_url = u.get("url", "")
            domain = u.get("domain", "")
            defanged = u.get("defanged") or defang_url(raw_url)

            url_id = f"url:{raw_url}"
            display_label = defanged[:40] + ("..." if len(defanged) > 40 else "")
            add_node(url_id, "url", raw_url, display_label)
            add_edge(root_id, url_id, "contains_url", "Contains URL")

            if domain:
                dom_id = f"domain:{domain}"
                add_node(dom_id, "domain", domain, domain)
                add_edge(url_id, dom_id, "hosted_by", "Hosted By")

        # 5. Attachments
        for att in parsed.attachments:
            att_id = f"file:{att.sha256[:12]}"
            label = f"{att.filename}"
            risk = "malicious" if att.is_macro else "neutral"
            add_node(att_id, "hash", att.sha256, label, risk=risk, meta={"sha256": att.sha256, "is_macro": att.is_macro})
            add_edge(root_id, att_id, "attaches_file", "Attachment")

        # 6. QR Codes
        if qr_codes:
            for idx, qr in enumerate(qr_codes):
                qr_text = qr.get("decoded_text", "")
                qr_defanged = qr.get("defanged_text") or defang_url(qr_text)
                qr_id = f"qr:{idx}"
                label = f"QR: {qr_defanged[:30]}"
                add_node(qr_id, "qr_url", qr_text, label, risk="suspicious")
                add_edge(root_id, qr_id, "embedded_qr", "Embedded QR")

        return IndicatorGraphResponse(
            nodes=list(nodes.values()),
            edges=edges,
        )
