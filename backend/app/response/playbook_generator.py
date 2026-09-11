"""
Automated Incident Response Playbook Generator for MailRecon AI.
Synthesizes threat classification, financial forensics, and technical IOCs
into actionable, prioritized containment workflows across Gateway, EDR, IAM, and Legal/Financial pillars.
"""
from email.utils import parseaddr
import enum
import logging
from typing import Any, Dict, List, Optional, Set

from app.schemas.analysis import PlaybookItem, PlaybookResponse

logger = logging.getLogger("mailrecon.response.playbook_generator")


class ResponsePillar(str, enum.Enum):
    EMAIL_GATEWAY = "EMAIL_GATEWAY"
    ENDPOINT_EDR = "ENDPOINT_EDR"
    IDENTITY_IAM = "IDENTITY_IAM"
    FINANCIAL_LEGAL = "FINANCIAL_LEGAL"


class ActionPriority(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


PILLAR_LABELS = {
    ResponsePillar.EMAIL_GATEWAY.value: "Email Gateway (M365)",
    ResponsePillar.ENDPOINT_EDR.value: "Endpoint & EDR",
    ResponsePillar.IDENTITY_IAM.value: "Identity & IAM",
    ResponsePillar.FINANCIAL_LEGAL.value: "Financial & Wire Fraud",
}


class PlaybookGenerator:
    """
    Generates deterministic, context-aware containment playbooks for SOC analysts.
    """

    @classmethod
    def generate(
        cls,
        case_id: str,
        parsed_email: Any,
        threat_classification: Optional[Dict[str, Any]] = None,
        financial_forensics: Optional[Dict[str, Any]] = None,
        origin_profile: Optional[Dict[str, Any]] = None,
        dns_validation: Optional[Dict[str, Any]] = None,
        completed_action_ids: Optional[Set[str]] = None,
    ) -> PlaybookResponse:
        completed_set = completed_action_ids or set()
        items: List[PlaybookItem] = []

        # Extract message metadata
        from_raw = ""
        subject = ""
        recipient = ""
        attachments = []
        urls = []

        if parsed_email is not None:
            if hasattr(parsed_email, "headers_json"):
                headers = parsed_email.headers_json or {}
                from_raw = headers.get("from") or ""
                subject = headers.get("subject") or ""
                recipient = headers.get("to") or ""
                attachments = parsed_email.attachments_json or []
                urls = parsed_email.urls_json or []
            elif isinstance(parsed_email, dict):
                headers = parsed_email.get("headers_json") or {}
                from_raw = headers.get("from") or ""
                subject = headers.get("subject") or ""
                recipient = headers.get("to") or ""
                attachments = parsed_email.get("attachments_json") or []
                urls = parsed_email.get("urls_json") or []

        _, from_email = parseaddr(from_raw)
        from_domain = from_email.split("@")[-1].lower().strip() if "@" in from_email else ""
        _, to_email = parseaddr(recipient)

        threat_cat = (threat_classification or {}).get("primary_category", "LEGITIMATE")
        orig_ip = (origin_profile or {}).get("originating_ip")
        cid_short = case_id[:8]

        # ----------------------------------------------------
        # 1. EMAIL GATEWAY ACTIONS
        # ----------------------------------------------------
        if from_domain:
            act_id = f"act-gw-block-domain-{cid_short}"
            items.append(
                PlaybookItem(
                    action_id=act_id,
                    pillar=ResponsePillar.EMAIL_GATEWAY.value,
                    pillar_label=PILLAR_LABELS[ResponsePillar.EMAIL_GATEWAY.value],
                    priority=ActionPriority.CRITICAL.value if threat_cat != "LEGITIMATE" else ActionPriority.LOW.value,
                    title=f"Block Sender Domain on Mail Gateway ({from_domain})",
                    description=f"Add sender domain '{from_domain}' to tenant perimeter blocklist to drop incoming emails.",
                    target_asset=from_domain,
                    automated_script=(
                        f"# Microsoft 365 Exchange Online PowerShell\n"
                        f'New-TenantAllowBlockListItems -ListType Sender -Block -Entries "{from_domain}" '
                        f'-ExpirationDate (Get-Date).AddDays(90) -Notes "MailRecon Case {cid_short}"'
                    ),
                    script_language="powershell",
                    manual_steps=[
                        f"Navigate to Microsoft Defender portal -> Threat policies -> Tenant Allow/Block Lists",
                        f"Verify entry for {from_domain} is set to Block with 90-day expiry",
                    ],
                    completed=act_id in completed_set,
                )
            )

        if orig_ip and not (origin_profile or {}).get("is_private"):
            act_id = f"act-gw-block-ip-{cid_short}"
            is_anon = (origin_profile or {}).get("is_anonymized", False)
            infra_label = (origin_profile or {}).get("infra_label", "Standard Ingress Node")
            items.append(
                PlaybookItem(
                    action_id=act_id,
                    pillar=ResponsePillar.EMAIL_GATEWAY.value,
                    pillar_label=PILLAR_LABELS[ResponsePillar.EMAIL_GATEWAY.value],
                    priority=ActionPriority.HIGH.value if is_anon else ActionPriority.MEDIUM.value,
                    title=f"Drop Originating IP on Perimeter Firewall ({orig_ip})",
                    description=f"Block incoming traffic from originating node '{orig_ip}' ({infra_label}) at perimeter border gateways.",
                    target_asset=orig_ip,
                    automated_script=(
                        f"# Linux iptables perimeter rule\n"
                        f'sudo iptables -I INPUT -s {orig_ip} -j DROP -m comment --comment "MailRecon Case {cid_short}"'
                    ),
                    script_language="bash",
                    manual_steps=[
                        f"Confirm {orig_ip} is not an internal corporate relay or trusted partner IP",
                        f"Add {orig_ip} to Edge Firewall blocklist",
                    ],
                    completed=act_id in completed_set,
                )
            )

        if subject or from_email:
            act_id = f"act-gw-purge-inbox-{cid_short}"
            is_crit = threat_cat in ["CREDENTIAL_PHISHING", "MALWARE_DELIVERY", "PAYMENT_DIVERSION", "CEO_IMPERSONATION"]
            items.append(
                PlaybookItem(
                    action_id=act_id,
                    pillar=ResponsePillar.EMAIL_GATEWAY.value,
                    pillar_label=PILLAR_LABELS[ResponsePillar.EMAIL_GATEWAY.value],
                    priority=ActionPriority.CRITICAL.value if is_crit else ActionPriority.MEDIUM.value,
                    title="Tenant-Wide Inbox Message Trace & Hard Delete Purge",
                    description="Search all corporate inboxes for this delivery and purge matching items before further user interaction.",
                    target_asset=subject or from_email,
                    automated_script=(
                        f"# Microsoft 365 Compliance Search & Purge\n"
                        f'$SearchName = "MailRecon_Purge_{cid_short}"\n'
                        f'New-ComplianceSearch -Name $SearchName -ExchangeLocation All '
                        f'-ContentMatchQuery \'(Subject:"{subject}") AND (From:"{from_email}")\'\n'
                        f'Start-ComplianceSearch -Identity $SearchName\n'
                        f'# Execute hard delete once search finishes:\n'
                        f'New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType HardDelete'
                    ),
                    script_language="powershell",
                    manual_steps=[
                        "Review Compliance Search results in Purview Security center",
                        "Verify total number of delivered copies across tenant mailboxes",
                    ],
                    completed=act_id in completed_set,
                )
            )

        # ----------------------------------------------------
        # 2. ENDPOINT & EDR ACTIONS
        # ----------------------------------------------------
        if attachments:
            for att in attachments:
                att_sha = att.get("sha256")
                att_name = att.get("filename", "attachment.bin")
                if att_sha:
                    act_id = f"act-edr-block-hash-{att_sha[:8]}"
                    items.append(
                        PlaybookItem(
                            action_id=act_id,
                            pillar=ResponsePillar.ENDPOINT_EDR.value,
                            pillar_label=PILLAR_LABELS[ResponsePillar.ENDPOINT_EDR.value],
                            priority=ActionPriority.CRITICAL.value if threat_cat == "MALWARE_DELIVERY" else ActionPriority.HIGH.value,
                            title=f"Block Malicious Attachment Hash on EDR ({att_name})",
                            description=f"Add SHA-256 hash '{att_sha}' to Defender / EDR custom indicator blocklist to prevent file execution on all workstations.",
                            target_asset=f"{att_name} ({att_sha[:16]}...)",
                            automated_script=(
                                f"# Microsoft Defender for Endpoint - Custom Indicator (PowerShell / API)\n"
                                f'$body = @{{\n'
                                f'    title = "MailRecon Case {cid_short} - {att_name}"\n'
                                f'    indicatorValue = "{att_sha}"\n'
                                f'    indicatorType = "FileSha256"\n'
                                f'    action = "BlockAndRemediate"\n'
                                f'    severity = "High"\n'
                                f'}} | ConvertTo-Json\n'
                                f'Invoke-RestMethod -Method Post -Uri "https://api.securitycenter.microsoft.com/api/indicators" -Body $body -Headers @{{Authorization = "Bearer $EDR_TOKEN"}}'
                            ),
                            script_language="powershell",
                            manual_steps=[
                                f"Verify file hash {att_sha} is cataloged in EDR IOC database",
                                f"Initiate enterprise threat hunt for prior execution instances",
                            ],
                            completed=act_id in completed_set,
                        )
                    )

        if to_email:
            act_id = f"act-edr-isolate-host-{cid_short}"
            items.append(
                PlaybookItem(
                    action_id=act_id,
                    pillar=ResponsePillar.ENDPOINT_EDR.value,
                    pillar_label=PILLAR_LABELS[ResponsePillar.ENDPOINT_EDR.value],
                    priority=ActionPriority.HIGH.value if threat_cat == "MALWARE_DELIVERY" else ActionPriority.LOW.value,
                    title=f"Isolate Recipient Endpoint from Corporate Network ({to_email})",
                    description=f"If target recipient clicked phishing payload or executed attachment, isolate machine via EDR agent to prevent lateral propagation.",
                    target_asset=to_email,
                    automated_script=(
                        f"# Microsoft Defender for Endpoint - Host Isolation\n"
                        f'$device = (Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/machines?email={to_email}" -Headers @{{Authorization = "Bearer $TOKEN"}}).value[0]\n'
                        f'Invoke-RestMethod -Method Post -Uri "https://api.securitycenter.microsoft.com/api/machines/$($device.id)/isolate" -Headers @{{Authorization = "Bearer $TOKEN"}} -Body (@{{Comment = "MailRecon Isolation"; IsolationType = "Full"}} | ConvertTo-Json)'
                    ),
                    script_language="powershell",
                    manual_steps=[
                        f"Check recipient proxy/firewall logs to confirm if link was visited",
                        f"Perform full antivirus/malware triage scan on recipient endpoint",
                    ],
                    completed=act_id in completed_set,
                )
            )

        # ----------------------------------------------------
        # 3. IDENTITY & ACCESS MANAGEMENT (IAM)
        # ----------------------------------------------------
        if to_email:
            act_id = f"act-iam-revoke-session-{cid_short}"
            is_phish = threat_cat in ["CREDENTIAL_PHISHING", "CEO_IMPERSONATION"]
            items.append(
                PlaybookItem(
                    action_id=act_id,
                    pillar=ResponsePillar.IDENTITY_IAM.value,
                    pillar_label=PILLAR_LABELS[ResponsePillar.IDENTITY_IAM.value],
                    priority=ActionPriority.CRITICAL.value if is_phish else ActionPriority.MEDIUM.value,
                    title=f"Revoke Active User Refresh Tokens & Invalidate Sessions ({to_email})",
                    description="Immediately invalidate all active browser sessions, OAuth refresh tokens, and cookies for target user account.",
                    target_asset=to_email,
                    automated_script=(
                        f"# Microsoft Graph / Azure AD PowerShell\n"
                        f'Revoke-AzureADUserAllRefreshToken -ObjectId "{to_email}"'
                    ),
                    script_language="powershell",
                    manual_steps=[
                        f"Verify in Azure AD Audit Logs that session revocation succeeded for {to_email}",
                        f"Check for abnormal sign-in locations or impossible travel anomalies in Entra ID Protection",
                    ],
                    completed=act_id in completed_set,
                )
            )

            act_id = f"act-iam-enforce-mfa-{cid_short}"
            items.append(
                PlaybookItem(
                    action_id=act_id,
                    pillar=ResponsePillar.IDENTITY_IAM.value,
                    pillar_label=PILLAR_LABELS[ResponsePillar.IDENTITY_IAM.value],
                    priority=ActionPriority.HIGH.value if is_phish else ActionPriority.LOW.value,
                    title=f"Enforce Immediate Password Reset & Verify FIDO2 MFA ({to_email})",
                    description="Force an immediate password change on next sign-in and inspect MFA registered devices for rogue additions.",
                    target_asset=to_email,
                    automated_script=(
                        f"# Force Password Reset on Next Sign-in\n"
                        f'Set-MsolUserPassword -UserPrincipalName "{to_email}" -ForceChangePassword $true'
                    ),
                    script_language="powershell",
                    manual_steps=[
                        f"Direct {to_email} to IT service desk for verified password reset",
                        f"Audit user registered authentication methods (verify no foreign authenticator apps or SMS numbers added)",
                    ],
                    completed=act_id in completed_set,
                )
            )

        # ----------------------------------------------------
        # 4. FINANCIAL & LEGAL ACTIONS
        # ----------------------------------------------------
        if financial_forensics and financial_forensics.get("is_financial_threat"):
            bank_accounts = financial_forensics.get("bank_accounts", [])
            routing_numbers = financial_forensics.get("routing_numbers", [])
            crypto_wallets = financial_forensics.get("crypto_wallets", [])
            amounts = financial_forensics.get("amounts_mentioned", [])
            target_str = ", ".join(bank_accounts[:2] + routing_numbers[:2]) or "Banking Artifacts"

            act_id = f"act-fin-freeze-wire-{cid_short}"
            items.append(
                PlaybookItem(
                    action_id=act_id,
                    pillar=ResponsePillar.FINANCIAL_LEGAL.value,
                    pillar_label=PILLAR_LABELS[ResponsePillar.FINANCIAL_LEGAL.value],
                    priority=ActionPriority.CRITICAL.value,
                    title=f"Emergency Hold: Freeze Outbound Wire Transfers ({target_str})",
                    description="Alert enterprise treasury and finance department immediately to halt all pending or scheduled disbursements matching these bank accounts.",
                    target_asset=target_str,
                    automated_script=(
                        f"# Internal Treasury Alert Notification (Webhook/Slack)\n"
                        f'$body = @{{\n'
                        f'    text = ":rotating_light: *SECURITY ALERT: EMERGENCY WIRE FREEZE REQUESTED*\n'
                        f'    *Case ID:* {case_id}\n'
                        f'    *Accounts:* {target_str}\n'
                        f'    *Amounts Mentioned:* {", ".join(amounts) if amounts else "N/A"}\n'
                        f'    *Action:* DO NOT AUTHORIZE TRANSFERS WITHOUT DUAL-APPROVAL."\n'
                        f'}} | ConvertTo-Json\n'
                        f'Invoke-RestMethod -Uri "$FINANCE_WEBHOOK_URL" -Method Post -Body $body -ContentType "application/json"'
                    ),
                    script_language="powershell",
                    manual_steps=[
                        "Contact corporate bank fraud desk immediately to recall any processed ACH or wire transfers within 24-48 hour clawback window",
                        "Audit ERP/accounting software (SAP, Oracle, NetSuite) for updated vendor bank details",
                    ],
                    completed=act_id in completed_set,
                )
            )

            act_id = f"act-fin-call-vendor-{cid_short}"
            items.append(
                PlaybookItem(
                    action_id=act_id,
                    pillar=ResponsePillar.FINANCIAL_LEGAL.value,
                    pillar_label=PILLAR_LABELS[ResponsePillar.FINANCIAL_LEGAL.value],
                    priority=ActionPriority.HIGH.value,
                    title="Conduct Out-of-Band Vendor Telephone Verification",
                    description="Contact supplier or vendor via established, trusted corporate telephone numbers on record (NEVER the contact number in the email).",
                    target_asset=from_domain or "Vendor Contact",
                    automated_script=None,
                    script_language="manual",
                    manual_steps=[
                        "Locate original signed vendor contract for official procurement contact number",
                        "Confirm verbal authorization with vendor CFO or controller",
                        "Document timestamp and verification outcome in case notes",
                    ],
                    completed=act_id in completed_set,
                )
            )

            act_id = f"act-fin-report-ic3-{cid_short}"
            items.append(
                PlaybookItem(
                    action_id=act_id,
                    pillar=ResponsePillar.FINANCIAL_LEGAL.value,
                    pillar_label=PILLAR_LABELS[ResponsePillar.FINANCIAL_LEGAL.value],
                    priority=ActionPriority.MEDIUM.value,
                    title="File FBI IC3 / Law Enforcement Cybercrime Report",
                    description="Submit fraudulent beneficiary details, IBAN/ABA routing numbers, and message headers to FBI IC3 (ic3.gov) for wire fraud recovery.",
                    target_asset="FBI IC3 Portal",
                    automated_script=None,
                    script_language="manual",
                    manual_steps=[
                        "Collect MailRecon PDF/JSON Forensic Report",
                        "Submit complaint via https://www.ic3.gov with full email headers and transaction hashes",
                    ],
                    completed=act_id in completed_set,
                )
            )

        completed_count = sum(1 for i in items if i.completed)
        critical_count = sum(1 for i in items if i.priority == ActionPriority.CRITICAL.value)

        return PlaybookResponse(
            case_id=case_id,
            total_actions=len(items),
            completed_actions=completed_count,
            critical_actions=critical_count,
            items=items,
        )
