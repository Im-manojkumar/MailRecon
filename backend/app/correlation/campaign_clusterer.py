"""
Threat Actor Campaign Correlation and Multi-Case Clustering Engine for MailRecon AI.
Analyzes cross-case infrastructure reuse (IPs, ASNs, Domains, Financial Coordinates, Hashes, Reply-To)
and clusters related incidents into cohesive threat actor campaigns.
"""
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.utils import parseaddr
import hashlib
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("mailrecon.correlation.campaign_clusterer")

EXCLUDED_GENERIC_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
    "aol.com",
    "protonmail.com",
    "proton.me",
    "mail.com",
    "zoho.com",
}


@dataclass
class SharedArtifact:
    kind: str  # "domain", "ip", "subnet", "iban", "routing_number", "crypto_wallet", "hash", "reply_to"
    value: str
    label: str
    occurrences: int
    case_ids: List[str]


@dataclass
class CampaignNode:
    id: str
    label: str
    type: str  # "case", "domain", "ip", "financial", "hash", "email"
    risk_level: str
    details: Dict[str, Any]


@dataclass
class CampaignEdge:
    source: str
    target: str
    label: str
    weight: float


@dataclass
class CampaignGraph:
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]


@dataclass
class CampaignCluster:
    campaign_id: str
    name: str
    threat_category: str
    threat_archetype: str
    risk_score: float
    confidence: float
    first_seen: str
    last_seen: str
    case_count: int
    cases: List[Dict[str, Any]]
    shared_artifacts: List[Dict[str, Any]]
    graph: Dict[str, Any]
    tactics: List[str]
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CampaignClusterer:
    """
    Engine to cluster disparate investigation cases into unified Threat Actor Campaigns.
    """

    @classmethod
    def extract_case_fingerprint(cls, case_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extracts correlation keys from case metadata, parsed email, and financial forensics.
        """
        case_id = str(case_data.get("id"))
        created_at = case_data.get("created_at") or datetime.now(timezone.utc).isoformat()
        if isinstance(created_at, datetime):
            created_at = created_at.isoformat()

        meta = case_data.get("metadata_json") or {}
        parsed = case_data.get("parsed_email") or {}
        headers = parsed.get("headers_json") or {}

        # 1. From & Reply-To
        from_raw = headers.get("from") or ""
        _, from_email = parseaddr(from_raw)
        from_email = from_email.lower().strip()
        from_domain = from_email.split("@")[-1] if "@" in from_email else ""

        reply_to_raw = headers.get("reply-to") or ""
        _, reply_to_email = parseaddr(reply_to_raw)
        reply_to_email = reply_to_email.lower().strip()

        # 2. Origin IP & ASN
        origin_profile = meta.get("origin_profile") or {}
        orig_ip = origin_profile.get("originating_ip")
        orig_asn = origin_profile.get("asn")
        is_private_ip = origin_profile.get("is_private", False)

        subnet = None
        if orig_ip and not is_private_ip:
            ip_parts = orig_ip.split(".")
            if len(ip_parts) == 4:
                subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

        # 3. Financial Artifacts
        fin = meta.get("financial_forensics") or {}
        ibans = [str(x).upper().replace(" ", "") for x in fin.get("bank_accounts", []) if x]
        routings = [str(x).strip() for x in fin.get("routing_numbers", []) if x]
        wallets = [w.get("address") for w in fin.get("crypto_wallets", []) if isinstance(w, dict) and w.get("address")]

        # 4. Attachment Hashes
        attachments = parsed.get("attachments_json") or []
        hashes = [a.get("sha256") for a in attachments if isinstance(a, dict) and a.get("sha256")]

        # 5. URLs / Domains
        urls = parsed.get("urls_json") or []
        url_domains = set()
        for u in urls:
            dom = u.get("domain") if isinstance(u, dict) else None
            if dom:
                url_domains.add(dom.lower())

        # 6. Threat score & category
        threat_class = meta.get("threat_classification") or {}
        risk_score_obj = meta.get("risk_score") or {}
        score_val = risk_score_obj.get("score")
        if score_val is None:
            score_val = 0.5
        score_val = float(score_val)

        category = threat_class.get("primary_category") or "LEGITIMATE"
        category_label = threat_class.get("category_label") or "Unknown"

        return {
            "case_id": case_id,
            "filename": case_data.get("filename") or f"Case_{case_id[:8]}",
            "created_at": created_at,
            "score": score_val,
            "threat_category": category,
            "category_label": category_label,
            "from_email": from_email,
            "from_domain": from_domain,
            "reply_to_email": reply_to_email,
            "recipient": headers.get("to") or "Target Recipient",
            "subject": headers.get("subject") or "Untitled",
            "orig_ip": orig_ip if not is_private_ip else None,
            "subnet": subnet,
            "asn": orig_asn,
            "ibans": ibans,
            "routings": routings,
            "wallets": wallets,
            "hashes": hashes,
            "url_domains": list(url_domains),
            "infra_label": origin_profile.get("infra_label"),
            "vendor_mismatch": fin.get("vendor_mismatch"),
        }

    @classmethod
    def cluster_cases(cls, cases_data: List[Dict[str, Any]]) -> List[CampaignCluster]:
        """
        Builds graph of cases and connects those with shared threat infrastructure.
        """
        if not cases_data:
            return []

        fingerprints = [cls.extract_case_fingerprint(c) for c in cases_data]

        # Artifact indexes mapping: artifact_key -> set of case_ids
        domain_index = defaultdict(set)
        reply_to_index = defaultdict(set)
        ip_index = defaultdict(set)
        iban_index = defaultdict(set)
        routing_index = defaultdict(set)
        wallet_index = defaultdict(set)
        hash_index = defaultdict(set)

        for fp in fingerprints:
            cid = fp["case_id"]

            # Domain index (excluding generic webmail)
            if fp["from_domain"] and fp["from_domain"] not in EXCLUDED_GENERIC_DOMAINS:
                domain_index[fp["from_domain"]].add(cid)

            # Reply-to index
            if fp["reply_to_email"] and fp["reply_to_email"] not in EXCLUDED_GENERIC_DOMAINS:
                reply_to_index[fp["reply_to_email"]].add(cid)

            # Ingress IP index
            if fp["orig_ip"]:
                ip_index[fp["orig_ip"]].add(cid)

            # Financial artifacts
            for iban in fp["ibans"]:
                iban_index[iban].add(cid)
            for r in fp["routings"]:
                routing_index[r].add(cid)
            for w in fp["wallets"]:
                wallet_index[w].add(cid)

            # Hashes
            for h in fp["hashes"]:
                hash_index[h].add(cid)

        # Adjacency graph between cases
        # case_id -> { neighbor_case_id: list_of_shared_reasons }
        adj: Dict[str, Dict[str, List[Tuple[str, str, float]]]] = defaultdict(lambda: defaultdict(list))

        def link_cases(case_set: Set[str], artifact_type: str, artifact_val: str, weight: float):
            cases_list = sorted(list(case_set))
            for i in range(len(cases_list)):
                for j in range(i + 1, len(cases_list)):
                    c1 = cases_list[i]
                    c2 = cases_list[j]
                    adj[c1][c2].append((artifact_type, artifact_val, weight))
                    adj[c2][c1].append((artifact_type, artifact_val, weight))

        for dom, cids in domain_index.items():
            if len(cids) > 1:
                link_cases(cids, "domain", dom, 0.85)

        for rto, cids in reply_to_index.items():
            if len(cids) > 1:
                link_cases(cids, "reply_to", rto, 0.90)

        for ip, cids in ip_index.items():
            if len(cids) > 1:
                link_cases(cids, "ip", ip, 0.80)

        for iban, cids in iban_index.items():
            if len(cids) > 1:
                link_cases(cids, "iban", iban, 1.0)

        for r, cids in routing_index.items():
            if len(cids) > 1:
                link_cases(cids, "routing", r, 0.95)

        for w, cids in wallet_index.items():
            if len(cids) > 1:
                link_cases(cids, "crypto_wallet", w, 1.0)

        for h, cids in hash_index.items():
            if len(cids) > 1:
                link_cases(cids, "hash", h, 0.95)

        # Find connected components via BFS
        visited = set()
        clusters: List[List[str]] = []

        all_case_ids = [fp["case_id"] for fp in fingerprints]
        for cid in all_case_ids:
            if cid in visited:
                continue
            # Start BFS
            component = []
            queue = [cid]
            visited.add(cid)

            while queue:
                curr = queue.pop(0)
                component.append(curr)
                for neighbor in adj[curr]:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)

            # We include clusters with >= 2 linked cases as active campaigns
            # Also allow standalone cases if user requests all or single-case view
            clusters.append(component)

        # Build CampaignCluster objects
        fp_by_id = {fp["case_id"]: fp for fp in fingerprints}
        campaign_results: List[CampaignCluster] = []

        for comp in clusters:
            # Only create campaign clusters for multi-case correlations or notable standalone threats
            is_campaign = len(comp) >= 2
            if not is_campaign:
                continue

            member_fps = [fp_by_id[cid] for cid in comp if cid in fp_by_id]
            if not member_fps:
                continue

            # Identify shared artifacts across this cluster
            shared_map: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
            for c1 in comp:
                for c2, reasons in adj[c1].items():
                    if c2 in comp:
                        for r_type, r_val, _ in reasons:
                            shared_map[(r_type, r_val)].add(c1)
                            shared_map[(r_type, r_val)].add(c2)

            shared_artifacts_list: List[Dict[str, Any]] = []
            for (r_type, r_val), c_set in shared_map.items():
                shared_artifacts_list.append({
                    "kind": r_type,
                    "value": r_val,
                    "label": f"{r_type.upper().replace('_', ' ')}: {r_val}",
                    "occurrences": len(c_set),
                    "case_ids": list(c_set),
                })

            shared_artifacts_list.sort(key=lambda x: x["occurrences"], reverse=True)

            # Determine dominant threat category
            cat_counts = defaultdict(int)
            for fp in member_fps:
                cat_counts[fp["threat_category"]] += 1
            primary_cat = max(cat_counts.items(), key=lambda x: x[1])[0]

            # Determine risk score & dates
            scores = [fp["score"] for fp in member_fps]
            max_score = max(scores) if scores else 0.5
            created_dates = sorted([fp["created_at"] for fp in member_fps])
            first_seen = created_dates[0] if created_dates else datetime.now(timezone.utc).isoformat()
            last_seen = created_dates[-1] if created_dates else datetime.now(timezone.utc).isoformat()

            # Synthesize campaign title & archetype name
            camp_name, archetype, desc = cls._generate_campaign_identity(
                primary_cat=primary_cat,
                shared_artifacts=shared_artifacts_list,
                member_fps=member_fps,
            )

            # Deterministic campaign ID from sorted case IDs
            hasher = hashlib.sha256()
            for cid in sorted(comp):
                hasher.update(cid.encode("utf-8"))
            camp_id = f"CMP-{hasher.hexdigest()[:8].upper()}"

            # Build sub-graph for this campaign
            graph = cls._build_campaign_graph(member_fps, shared_artifacts_list)

            # Extract tactics
            tactics = cls._extract_tactics(primary_cat, member_fps, shared_artifacts_list)

            cluster_obj = CampaignCluster(
                campaign_id=camp_id,
                name=camp_name,
                threat_category=primary_cat,
                threat_archetype=archetype,
                risk_score=round(max_score, 2),
                confidence=round(min(0.70 + (len(comp) * 0.08) + (len(shared_artifacts_list) * 0.05), 0.98), 2),
                first_seen=first_seen,
                last_seen=last_seen,
                case_count=len(comp),
                cases=member_fps,
                shared_artifacts=shared_artifacts_list,
                graph=graph,
                tactics=tactics,
                description=desc,
            )
            campaign_results.append(cluster_obj)

        # Sort campaigns by risk score and case count
        campaign_results.sort(key=lambda c: (c.risk_score, c.case_count), reverse=True)
        return campaign_results

    @classmethod
    def _generate_campaign_identity(
        cls,
        primary_cat: str,
        shared_artifacts: List[Dict[str, Any]],
        member_fps: List[Dict[str, Any]],
    ) -> Tuple[str, str, str]:
        """
        Synthesizes human-readable threat actor campaign name and technical description.
        """
        top_art = shared_artifacts[0] if shared_artifacts else None
        target_domains = {fp["recipient"].split("@")[-1] for fp in member_fps if "@" in fp["recipient"]}
        target_str = list(target_domains)[0] if target_domains else "Enterprise"

        if primary_cat == "PAYMENT_DIVERSION":
            archetype = "BEC / Wire Fraud Syndicate"
            lead_val = top_art["value"] if top_art else "Banking"
            name = f"Operation SilverWire: Payment Diversion Syndicate ({lead_val[:14]})"
            desc = (
                f"Coordinated Business Email Compromise and payment diversion wave targeting {target_str}. "
                f"Threat actors re-used shared banking coordinates across {len(member_fps)} intercepted communications."
            )
        elif primary_cat == "CREDENTIAL_PHISHING":
            archetype = "Credential Harvesting Ring"
            domain_lead = top_art["value"] if (top_art and top_art["kind"] == "domain") else (member_fps[0]["from_domain"] or "Phish")
            name = f"DarkHarvester: Credential Harvesting Campaign ({domain_lead})"
            desc = (
                f"Multi-wave credential phishing infrastructure targeting employee mailboxes. "
                f"Utilizes deceptive sender identities and shared authentication harvesting portals."
            )
        elif primary_cat == "MALWARE_DELIVERY":
            archetype = "Automated Malware / Dropper Distribution"
            name = f"VBA-Dropper Syndicate: Payload Distribution Wave"
            desc = (
                f"Active malware delivery campaign distributing weaponized attachments and macro payloads "
                f"across {len(member_fps)} distinct recipient endpoints."
            )
        elif primary_cat == "CEO_IMPERSONATION":
            archetype = "Executive Identity Spoofing Ring"
            name = f"Executive Ghost: C-Suite Impersonation Ring"
            desc = (
                f"Spear-phishing wave impersonating corporate executives to induce urgent confidential actions "
                f"or out-of-band wire authorizations."
            )
        elif primary_cat == "SPAM_RECONNAISSANCE":
            archetype = "High-Volume Reconnaissance & Spam Fleet"
            name = f"EchoScan: Automated Inbound Reconnaissance Fleet"
            desc = "Automated email reconnaissance fleet mapping valid enterprise mailboxes and evaluating perimeter defenses."
        else:
            archetype = "Coordinated Multi-Vector Threat"
            name = f"Cluster-{primary_cat.lower()}: Shared Infrastructure Wave"
            desc = f"Correlated email threat activity sharing infrastructure elements across {len(member_fps)} cases."

        return name, archetype, desc

    @classmethod
    def _build_campaign_graph(
        cls,
        member_fps: List[Dict[str, Any]],
        shared_artifacts: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Builds a force-directed node-link graph of Cases connected to shared Infrastructure artifacts.
        """
        nodes = []
        edges = []
        node_ids = set()

        # Add Case Nodes
        for fp in member_fps:
            cid = fp["case_id"]
            node_id = f"case-{cid}"
            if node_id not in node_ids:
                node_ids.add(node_id)
                nodes.append({
                    "id": node_id,
                    "label": fp["filename"],
                    "sublabel": f"{fp['threat_category']} ({int(fp['score'] * 100)}%)",
                    "type": "case",
                    "category": fp["threat_category"],
                    "risk_level": "critical" if fp["score"] >= 0.75 else ("high" if fp["score"] >= 0.5 else "medium"),
                    "details": {
                        "case_id": cid,
                        "subject": fp["subject"],
                        "from": fp["from_email"],
                        "to": fp["recipient"],
                        "score": fp["score"],
                    }
                })

        # Add Shared Artifact Nodes
        for art in shared_artifacts:
            art_id = f"art-{art['kind']}-{hashlib.sha256(art['value'].encode()).hexdigest()[:8]}"
            if art_id not in node_ids:
                node_ids.add(art_id)
                nodes.append({
                    "id": art_id,
                    "label": art["value"],
                    "sublabel": art["kind"].upper().replace("_", " "),
                    "type": art["kind"],  # "domain", "ip", "iban", "hash", "reply_to"
                    "category": "infrastructure",
                    "risk_level": "critical" if art["kind"] in ["iban", "hash", "crypto_wallet"] else "high",
                    "details": {
                        "occurrences": art["occurrences"],
                        "kind": art["kind"],
                        "value": art["value"],
                    }
                })

            # Connect each case that shares this artifact
            for cid in art["case_ids"]:
                case_node_id = f"case-{cid}"
                if case_node_id in node_ids:
                    edges.append({
                        "source": case_node_id,
                        "target": art_id,
                        "label": f"Uses {art['kind']}",
                        "weight": 1.0,
                    })

        return {"nodes": nodes, "edges": edges}

    @classmethod
    def _extract_tactics(
        cls,
        primary_cat: str,
        member_fps: List[Dict[str, Any]],
        shared_artifacts: List[Dict[str, Any]],
    ) -> List[str]:
        tactics = []
        if any(a["kind"] == "iban" for a in shared_artifacts):
            tactics.append("Payment Remittance Hijacking (IBAN Modification)")
        if any(a["kind"] == "reply_to" for a in shared_artifacts):
            tactics.append("Asymmetric Reply-To Manipulation (BEC Redirection)")
        if any(a["kind"] == "domain" for a in shared_artifacts):
            tactics.append("Infrastructure Re-use (Homograph / Spoofed Domain)")
        if any(a["kind"] == "ip" for a in shared_artifacts):
            tactics.append("Centralized Ingress MTA Routing")
        if any(a["kind"] == "hash" for a in shared_artifacts):
            tactics.append("Shared Dropper / Weaponized Macro Attachment")
        if any(fp.get("vendor_mismatch") for fp in member_fps):
            tactics.append("Vendor Identity Impersonation")

        if not tactics:
            tactics.append(f"Multi-Wave {primary_cat.replace('_', ' ').title()} Inbound Delivery")

        return tactics
