"""
Multi-Format Threat Intelligence and Detection Rule Exporter for MailRecon AI.
Generates:
1. STIX 2.1 JSON Cyber Threat Intelligence Bundle
2. YARA Rule (.yar) for email and file payload scanning
3. Sigma Rule (.yml) for SIEM log detection (Splunk, Elastic, Sentinel)
4. Snort / Suricata Rule (.rules) for network perimeter IDS/IPS
"""
from datetime import datetime, timezone
from email.utils import parseaddr
import json
import logging
import re
from typing import Any, Dict, List, Optional
import uuid

logger = logging.getLogger("mailrecon.export.ioc_exporter")


class IocExportEngine:
    """
    Engine synthesizing case forensic evidence into detection rule formats.
    """

    @classmethod
    def export_stix_bundle(
        cls,
        case_id: str,
        parsed_email: Any,
        findings: Optional[List[Any]] = None,
        indicators: Optional[List[Any]] = None,
        threat_classification: Optional[Dict[str, Any]] = None,
        financial_forensics: Optional[Dict[str, Any]] = None,
        origin_profile: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Generates an OASIS STIX 2.1 JSON Bundle.
        """
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        bundle_id = f"bundle--{uuid.uuid4()}"
        identity_id = f"identity--{uuid.uuid4()}"

        objects: List[Dict[str, Any]] = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": now_iso,
                "modified": now_iso,
                "name": "Mail-Recon AI Automated Forensic Engine",
                "identity_class": "system",
            }
        ]

        # Extract headers and body
        headers = {}
        urls = []
        attachments = []
        if hasattr(parsed_email, "headers_json"):
            headers = parsed_email.headers_json or {}
            urls = getattr(parsed_email, "urls_json", []) or []
            attachments = getattr(parsed_email, "attachments_json", []) or []
        elif hasattr(parsed_email, "headers"):
            headers = parsed_email.headers or {}
            urls = getattr(parsed_email, "urls", []) or []
            attachments = getattr(parsed_email, "attachments", []) or []
        elif isinstance(parsed_email, dict):
            headers = parsed_email.get("headers_json") or {}
            urls = parsed_email.get("urls_json") or []
            attachments = parsed_email.get("attachments_json") or []

        from_raw = headers.get("from") or ""
        _, from_email = parseaddr(from_raw)
        from_domain = from_email.split("@")[-1].lower().strip() if "@" in from_email else ""

        # Process structured indicators if passed
        existing_patterns = set()
        if indicators:
            for ind in indicators:
                ind_type = getattr(ind, "type", None) or (ind.get("type") if isinstance(ind, dict) else None)
                val = getattr(ind, "value", None) or (ind.get("value") if isinstance(ind, dict) else None)
                if not ind_type or not val:
                    continue
                stix_pattern = None
                if ind_type == "domain":
                    stix_pattern = f"[domain-name:value = '{val}']"
                elif ind_type == "ip":
                    stix_pattern = f"[ipv4-addr:value = '{val}']"
                elif ind_type == "url":
                    clean_u = val.replace("'", "\\'")
                    stix_pattern = f"[url:value = '{clean_u}']"
                elif ind_type == "hash":
                    stix_pattern = f"[file:hashes.'SHA-256' = '{val}']"

                if stix_pattern and stix_pattern not in existing_patterns:
                    existing_patterns.add(stix_pattern)
                    objects.append({
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": f"indicator--{uuid.uuid4()}",
                        "created": now_iso,
                        "modified": now_iso,
                        "name": f"Threat Indicator ({ind_type}): {val[:50]}",
                        "pattern": stix_pattern,
                        "pattern_type": "stix",
                        "valid_from": now_iso,
                        "created_by_ref": identity_id,
                    })

        # 1. Sender Domain Indicator
        if from_domain:
            pat = f"[domain-name:value = '{from_domain}']"
            if pat not in existing_patterns:
                existing_patterns.add(pat)
                domain_ind_id = f"indicator--{uuid.uuid4()}"
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": domain_ind_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "name": f"Malicious Email Sender Domain: {from_domain}",
                    "description": f"Phishing / threat domain observed in MailRecon Case {case_id[:8]}",
                    "indicator_types": ["malicious-activity"],
                    "pattern": pat,
                    "pattern_type": "stix",
                    "valid_from": now_iso,
                    "created_by_ref": identity_id,
                })

        # 2. Originating Ingress IP Indicator
        orig_ip = (origin_profile or {}).get("originating_ip")
        if orig_ip and not (origin_profile or {}).get("is_private"):
            pat = f"[ipv4-addr:value = '{orig_ip}']"
            if pat not in existing_patterns:
                existing_patterns.add(pat)
                ip_ind_id = f"indicator--{uuid.uuid4()}"
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ip_ind_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "name": f"Threat Originating Ingress IP: {orig_ip}",
                    "description": f"Earliest reliable ingress node observed in MailRecon Case {case_id[:8]}",
                    "indicator_types": ["anonymized" if (origin_profile or {}).get("is_anonymized") else "malicious-activity"],
                    "pattern": pat,
                    "pattern_type": "stix",
                    "valid_from": now_iso,
                    "created_by_ref": identity_id,
                })

        # 3. URL Indicators
        for u in urls[:5]:
            url_str = u.get("url") if isinstance(u, dict) else getattr(u, "url", None)
            if url_str:
                clean_url = url_str.replace("'", "\\'")
                pat = f"[url:value = '{clean_url}']"
                if pat not in existing_patterns:
                    existing_patterns.add(pat)
                    u_ind_id = f"indicator--{uuid.uuid4()}"
                    objects.append({
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": u_ind_id,
                        "created": now_iso,
                        "modified": now_iso,
                        "name": f"Extracted Phishing Link: {url_str[:50]}",
                        "pattern": pat,
                        "pattern_type": "stix",
                        "valid_from": now_iso,
                        "created_by_ref": identity_id,
                    })

        # 4. Attachment File Hash Indicators
        for att in attachments[:5]:
            sha256 = att.get("sha256") if isinstance(att, dict) else getattr(att, "sha256", None)
            fn = att.get("filename") if isinstance(att, dict) else getattr(att, "filename", "attachment")
            if sha256:
                pat = f"[file:hashes.'SHA-256' = '{sha256}']"
                if pat not in existing_patterns:
                    existing_patterns.add(pat)
                    h_ind_id = f"indicator--{uuid.uuid4()}"
                    objects.append({
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": h_ind_id,
                        "created": now_iso,
                        "modified": now_iso,
                        "name": f"Malicious Attachment Hash: {fn}",
                        "pattern": pat,
                        "pattern_type": "stix",
                        "valid_from": now_iso,
                        "created_by_ref": identity_id,
                    })

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }

    @classmethod
    def export_yara_rule(
        cls,
        case_id: str,
        parsed_email: Any,
        findings: Optional[List[Any]] = None,
        threat_classification: Optional[Dict[str, Any]] = None,
        macros: Optional[List[Dict[str, Any]]] = None,
        **kwargs,
    ) -> str:
        """
        Generates a YARA rule for message and payload scanning.
        """
        clean_id = re.sub(r"[^a-zA-Z0-9_]", "_", case_id)
        category = (threat_classification or {}).get("primary_category", "SUSPICIOUS_EMAIL")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        headers = {}
        urls = []
        body_text = ""
        if hasattr(parsed_email, "headers_json"):
            headers = parsed_email.headers_json or {}
            urls = getattr(parsed_email, "urls_json", []) or []
            body_text = getattr(parsed_email, "body_text", "") or ""
        elif hasattr(parsed_email, "headers"):
            headers = parsed_email.headers or {}
            urls = getattr(parsed_email, "urls", []) or []
            body_text = getattr(parsed_email, "body_text", "") or ""
        elif isinstance(parsed_email, dict):
            headers = parsed_email.get("headers_json") or {}
            urls = parsed_email.get("urls_json") or []
            body_text = parsed_email.get("body_text") or ""

        subject = headers.get("subject") or ""
        clean_subject = re.sub(r'[\"\\]', "", subject)[:60]
        from_raw = headers.get("from") or ""
        _, from_email = parseaddr(from_raw)

        lines = [
            f"rule MailRecon_Threat_Hunting_{clean_id} {{",
            "    meta:",
            f'        description = "MailRecon AI Detection Rule - Case {case_id[:8]}"',
            '        author = "MailRecon AI SOC"',
            f'        date = "{today}"',
            f'        threat_category = "{category}"',
            f'        reference = "case:{case_id}"',
            "    strings:",
        ]

        # Add subject string
        if clean_subject:
            lines.append(f'        $subject = "{clean_subject}" nocase')
        else:
            lines.append('        $subject = "Suspicious Message" nocase')

        # Add sender string
        if from_email:
            clean_from = from_email.replace('"', '')
            lines.append(f'        $sender = "{clean_from}" nocase')

        # Add URL strings
        str_idx = 0
        for u in urls[:3]:
            u_str = u.get("url") if isinstance(u, dict) else getattr(u, "url", "")
            if u_str and len(u_str) < 120:
                clean_u = re.sub(r'[\"\\]', "", u_str)
                lines.append(f'        $url_{str_idx} = "{clean_u}"')
                str_idx += 1

        # Add macro signatures if present
        if macros:
            lines.append('        $vba_exec = "AutoOpen" nocase')
            lines.append('        $vba_shell = "WScript.Shell" nocase')

        lines.extend([
            "    condition:",
            "        $subject and ($sender or any of ($url*))",
            "}",
            "",
        ])

        return "\n".join(lines)

    @classmethod
    def export_sigma_rule(
        cls,
        case_id: str,
        parsed_email: Any,
        findings: Optional[List[Any]] = None,
        threat_classification: Optional[Dict[str, Any]] = None,
        origin_profile: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> str:
        """
        Generates a Sigma YAML rule for SIEM detection.
        """
        headers = {}
        urls = []
        if hasattr(parsed_email, "headers_json"):
            headers = parsed_email.headers_json or {}
            urls = getattr(parsed_email, "urls_json", []) or []
        elif hasattr(parsed_email, "headers"):
            headers = parsed_email.headers or {}
            urls = getattr(parsed_email, "urls", []) or []
        elif isinstance(parsed_email, dict):
            headers = parsed_email.get("headers_json") or {}
            urls = parsed_email.get("urls_json") or []

        subject = headers.get("subject") or "Suspicious Email"
        clean_subj = subject.replace('"', '').replace("'", "")[:60]
        from_raw = headers.get("from") or ""
        _, from_email = parseaddr(from_raw)
        category = (threat_classification or {}).get("primary_category", "PHISHING")
        today = datetime.now(timezone.utc).strftime("%Y/%m/%d")

        rule_domains = []
        if "@" in from_email:
            rule_domains.append(from_email.split("@")[-1].lower())
        for u in urls[:2]:
            dom = u.get("domain") if isinstance(u, dict) else getattr(u, "domain", None)
            if dom and dom not in rule_domains:
                rule_domains.append(dom)

        domains_str = "\n".join([f"            - '{d}'" for d in rule_domains]) or f"            - '{from_email}'"

        rule_yaml = f"""title: Mail-Recon Detection - {clean_subj}
id: {uuid.uuid4()}
status: experimental
description: Detects inbound email threat activity corresponding to MailRecon Case {case_id[:8]} ({category}).
references:
    - https://mailrecon.local/cases/{case_id}
author: MailRecon AI SOC
date: {today}
logsource:
    category: email
    product: m365
detection:
    selection_sender:
        Sender: '{from_email or "unknown@sender.com"}'
    selection_subject:
        Subject|contains: '{clean_subj}'
    selection_domains:
        Recipient|contains:
{domains_str}
    condition: 1 of selection_*
fields:
    - Sender
    - Recipient
    - Subject
    - MessageId
falsepositives:
    - Legitimate administrative correspondence matching subject template
level: high
tags:
    - attack.initial_access
    - attack.t1566
    - attack.t1566.001
"""
        return rule_yaml

    @classmethod
    def export_snort_rules(
        cls,
        case_id: str,
        parsed_email: Any,
        findings: Optional[List[Any]] = None,
        origin_profile: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> str:
        """
        Generates Snort / Suricata network IDS rules.
        """
        urls = []
        if hasattr(parsed_email, "urls_json"):
            urls = parsed_email.urls_json or []
        elif hasattr(parsed_email, "urls"):
            urls = parsed_email.urls or []
        elif isinstance(parsed_email, dict):
            urls = parsed_email.get("urls_json") or []

        orig_ip = (origin_profile or {}).get("originating_ip")
        rules = [
            f"# MailRecon AI Network Signatures - Case {case_id[:8]}",
            f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
        ]

        sid = 9000101
        # Ingress IP rule
        if orig_ip and not (origin_profile or {}).get("is_private"):
            rules.append(
                f'alert tcp {orig_ip} any -> $HOME_NET [25,587] '
                f'(msg:"MAILRECON Suspicious Originating MTA Connection ({orig_ip})"; '
                f'flow:to_server,established; classtype:bad-unknown; sid:{sid}; rev:1;)'
            )
            sid += 1

        # URL host rules
        for u in urls[:5]:
            url_str = u.get("url") if isinstance(u, dict) else getattr(u, "url", "")
            domain_str = u.get("domain") if isinstance(u, dict) else getattr(u, "domain", "")
            target_host = domain_str
            if not target_host:
                m = re.search(r"https?://([^/:\s]+)", url_str)
                if m:
                    target_host = m.group(1)

            if target_host:
                rules.append(
                    f'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS '
                    f'(msg:"MAILRECON Outbound Connection to Intercepted Phishing Host ({target_host})"; '
                    f'flow:to_server,established; content:"{target_host}"; http_header; '
                    f'classtype:trojan-activity; sid:{sid}; rev:1;)'
                )
                sid += 1

        if len(rules) <= 3:
            rules.append(
                f'alert tcp $HOME_NET any -> $EXTERNAL_NET [80,443] '
                f'(msg:"MAILRECON Threat Activity Indicator - Case {case_id[:8]}"; '
                f'flow:to_server,established; classtype:trojan-activity; sid:{sid}; rev:1;)'
            )

        return "\n".join(rules) + "\n"
