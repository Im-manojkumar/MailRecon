import asyncio
import logging
import uuid

from sqlalchemy import select

from app.database import async_session_maker
from app.models.case import Case, CaseStatus
from app.models.parsed_email import ParsedEmail
from app.parser.email_parser import EmailParser
from app.storage.deps import get_evidence_store

logger = logging.getLogger(__name__)


async def _async_process_case(case_id: uuid.UUID) -> bool:
    """Async implementation of case ingestion, verification, and email parsing."""
    storage = get_evidence_store()
    
    async with async_session_maker() as session:
        result = await session.execute(select(Case).where(Case.id == case_id))
        case = result.scalars().first()
        if not case:
            logger.error(f"Case {case_id} not found in database.")
            return False

        logger.info(f"Processing case {case_id} ({case.filename})")
        case.status = CaseStatus.processing
        await session.commit()
        await session.refresh(case)

        # 1. Verify evidence existence and SHA-256 integrity
        if not await storage.exists(case.storage_key):
            logger.error(f"Evidence file {case.storage_key} missing for case {case_id}")
            case.status = CaseStatus.failed
            case.metadata_json = {"error": "Evidence file missing from storage"}
            await session.commit()
            return False

        is_valid = await storage.verify_integrity(case.storage_key, case.original_sha256)
        if not is_valid:
            logger.error(f"Integrity check failed for case {case_id}")
            case.status = CaseStatus.failed
            case.metadata_json = {"error": "Evidence integrity check failed: SHA-256 mismatch"}
            await session.commit()
            return False

        logger.info(f"Case {case_id} evidence verified (SHA-256: {case.original_sha256}). Parsing email...")

        # 2. Read raw evidence and parse email structure
        raw_bytes = await storage.get(case.storage_key)
        parsed_result = EmailParser.parse(raw_bytes)

        # 3. Store attachments safely in evidence store
        attachments_json = []
        for att in parsed_result.attachments:
            att_storage_key = f"cases/{case.original_sha256}/attachments/{att.sha256}"
            if att.raw_bytes:
                await storage.put(att_storage_key, att.raw_bytes)
            att.storage_key = att_storage_key

            attachments_json.append({
                "filename": att.filename,
                "content_type": att.content_type,
                "size": att.size,
                "sha256": att.sha256,
                "is_macro": att.is_macro,
                "is_inline": att.is_inline,
                "content_id": att.content_id,
                "storage_key": att.storage_key,
            })

        # 4. Save ParsedEmail record to database
        pe_res = await session.execute(select(ParsedEmail).where(ParsedEmail.case_id == case.id))
        parsed_record = pe_res.scalars().first()
        if not parsed_record:
            parsed_record = ParsedEmail(case_id=case.id)
            session.add(parsed_record)

        parsed_record.headers_json = parsed_result.headers
        parsed_record.body_text = parsed_result.body_text
        parsed_record.body_html = parsed_result.body_html
        parsed_record.attachments_json = attachments_json
        parsed_record.urls_json = parsed_result.urls
        parsed_record.auth_results_json = parsed_result.auth_results
        parsed_record.received_chain_json = parsed_result.received_chain

        # 5. Execute Route Analysis, Origin Tracing & Infrastructure Categorization
        from email.utils import parseaddr
        from app.enrichment.route_analyzer import RouteAnalyzer
        from app.parser.dns_validator import DnsProtocolValidator
        from app.enrichment.domain_intel import DomainIntelService

        current_metadata = dict(case.metadata_json or {})

        route_res = RouteAnalyzer.analyze(parsed_result.received_chain)
        current_metadata["route_analysis"] = route_res.to_dict()

        orig_node = route_res.originating_node or {}
        orig_ip = orig_node.get("ip")
        infra_tag = orig_node.get("infra_tag") or {}

        origin_profile = {
            "originating_ip": orig_ip,
            "country": (orig_node.get("geoip") or {}).get("country"),
            "country_code": (orig_node.get("geoip") or {}).get("country_code"),
            "city": (orig_node.get("geoip") or {}).get("city"),
            "isp": (orig_node.get("geoip") or {}).get("isp"),
            "org": (orig_node.get("geoip") or {}).get("org"),
            "asn": (orig_node.get("geoip") or {}).get("asn"),
            "infra_type": infra_tag.get("infra_type"),
            "infra_label": infra_tag.get("label"),
            "origin_confidence": route_res.origin_confidence,
            "is_anonymized": infra_tag.get("is_anonymized", False),
        }
        current_metadata["origin_profile"] = origin_profile

        # 6. Live DNS Protocol Validation and Domain Intelligence
        from_raw = parsed_result.headers.get("from") or parsed_result.headers.get("From") or ""
        _, from_addr = parseaddr(from_raw)
        from_domain = from_addr.split("@")[-1].lower().strip() if "@" in from_addr else ""

        rp_raw = parsed_result.headers.get("return-path") or parsed_result.headers.get("Return-Path") or ""
        _, rp_addr = parseaddr(rp_raw)
        rp_domain = rp_addr.split("@")[-1].lower().strip() if "@" in rp_addr else None

        dkim_domain = None
        if parsed_result.auth_results and parsed_result.auth_results.get("dkim"):
            dkim_domain = parsed_result.auth_results["dkim"].get("domain")

        msg_id = parsed_result.headers.get("message-id") or parsed_result.headers.get("Message-ID")

        dns_res = DnsProtocolValidator.validate_domain(
            from_domain=from_domain,
            originating_ip=orig_ip,
            return_path_domain=rp_domain,
            dkim_domain=dkim_domain,
            message_id=msg_id,
        )
        current_metadata["dns_validation"] = dns_res.to_dict()

        domain_prof = DomainIntelService.lookup(from_domain)
        current_metadata["domain_intel"] = domain_prof.to_dict()

        # 7. Run deterministic security detectors and combine with protocol/infra findings
        from app.detectors import run_all_detectors
        from app.detectors.base import FindingData
        from app.models.finding import Finding, SeverityLevel

        findings_data = run_all_detectors(parsed_result)

        # Ingest origin infrastructure findings
        if infra_tag.get("infra_type") == "TOR_EXIT":
            findings_data.append(FindingData(
                detector="origin_traceability",
                severity=SeverityLevel.critical,
                title="Originating Node: TOR Anonymization Network",
                detail="Forensic route analysis traced the earliest reliable sending node to a known Onion Router (TOR) exit node. Legitimate enterprise communications do not originate from darknet anonymizers.",
                evidence_ref="route.originating_node",
                confidence=0.98,
                raw_evidence=orig_node,
            ))
        elif infra_tag.get("infra_type") == "RESIDENTIAL_BROADBAND" and not (orig_node.get("geoip") or {}).get("is_private"):
            findings_data.append(FindingData(
                detector="origin_traceability",
                severity=SeverityLevel.high,
                title=f"Direct Residential Broadband Origin ({infra_tag.get('provider') or 'Consumer ISP'})",
                detail="The email originated directly from consumer broadband or residential cable/DSL without routing through an authorized enterprise mail server, indicating a compromised home/office machine or botnet node.",
                evidence_ref="route.originating_node",
                confidence=0.88,
                raw_evidence=orig_node,
            ))
        elif infra_tag.get("infra_type") == "VPN_PROXY":
            findings_data.append(FindingData(
                detector="origin_traceability",
                severity=SeverityLevel.medium,
                title=f"Anonymizing VPN / Proxy Origin ({infra_tag.get('provider') or 'Commercial VPN'})",
                detail="Transmission originated from an anonymizing commercial VPN or proxy gateway, obscuring the true physical origin.",
                evidence_ref="route.originating_node",
                confidence=0.85,
                raw_evidence=orig_node,
            ))

        # Ingest domain age and protocol findings
        if domain_prof.is_newly_registered and domain_prof.domain_age_days is not None:
            findings_data.append(FindingData(
                detector="domain_intelligence",
                severity=SeverityLevel.critical,
                title=f"Newly Registered Sender Domain ({domain_prof.domain_age_days} Days Old)",
                detail=f"The sender domain '{from_domain}' was registered only {domain_prof.domain_age_days} days ago (Registrar: {domain_prof.registrar or 'Public Registrar'}). Freshly registered domains are heavily correlated with targeted phishing campaigns.",
                evidence_ref="domain_intel.created_at",
                confidence=0.95,
                raw_evidence=domain_prof.to_dict(),
            ))
        elif domain_prof.is_recent and domain_prof.domain_age_days is not None:
            findings_data.append(FindingData(
                detector="domain_intelligence",
                severity=SeverityLevel.medium,
                title=f"Recently Registered Sender Domain ({domain_prof.domain_age_days} Days Old)",
                detail=f"The sender domain '{from_domain}' was registered {domain_prof.domain_age_days} days ago. Domains under 90 days old present elevated risk of lookalike spoofing.",
                evidence_ref="domain_intel.created_at",
                confidence=0.80,
                raw_evidence=domain_prof.to_dict(),
            ))

        if dns_res.mx.is_send_only:
            findings_data.append(FindingData(
                detector="protocol_forensics",
                severity=SeverityLevel.medium,
                title="Send-Only Burner Domain (No Inbound MX Records)",
                detail=f"Domain '{from_domain}' has NO published MX records and cannot receive incoming mail. Adversaries frequently use disposable send-only domains for unrepliable attack campaigns.",
                evidence_ref="dns.mx",
                confidence=0.90,
                raw_evidence={"mx": dns_res.mx.__dict__},
            ))

        if dns_res.spf.is_ip_authorized is False and dns_res.spf.default_policy in ["fail", "softfail"]:
            findings_data.append(FindingData(
                detector="protocol_forensics",
                severity=SeverityLevel.high,
                title="Originating Node Not Authorized in Domain SPF Record",
                detail=f"The originating IP '{orig_ip}' is not authorized in '{from_domain}' published SPF record ({dns_res.spf.raw_record}).",
                evidence_ref="dns.spf",
                confidence=0.94,
                raw_evidence={"originating_ip": orig_ip, "spf": dns_res.spf.__dict__},
            ))

        # Run Payment Diversion and Financial Fraud Detector
        from app.detectors.financial_fraud import FinancialFraudDetector
        raw_atts = [{"filename": a.filename, "content_type": a.content_type} for a in parsed_result.attachments]
        fin_res = FinancialFraudDetector.analyze(
            subject=parsed_result.headers.get("subject", ""),
            body_text=parsed_result.body_text or "",
            from_header=from_raw,
            reply_to=parsed_result.headers.get("reply-to"),
            attachments=raw_atts,
        )
        current_metadata["financial_forensics"] = fin_res.to_dict()

        if fin_res.is_financial_threat:
            sev = SeverityLevel.critical if fin_res.risk_level == "critical" else SeverityLevel.high
            fin_detail = f"Message exhibits payment redirection patterns (Indicators: {', '.join(fin_res.diversion_indicators[:3])})."
            if fin_res.vendor_mismatch:
                fin_detail += f" {fin_res.vendor_mismatch}"
            findings_data.append(FindingData(
                detector="financial_fraud",
                severity=sev,
                title="Payment Diversion / BEC Financial Wire Fraud Detected",
                detail=fin_detail,
                evidence_ref="body.financial_forensics",
                confidence=max(0.85, fin_res.threat_score),
                raw_evidence=fin_res.to_dict(),
            ))

        for fd in findings_data:
            finding_record = Finding(
                case_id=case.id,
                detector=fd.detector,
                severity=fd.severity,
                title=fd.title,
                detail=fd.detail,
                evidence_ref=fd.evidence_ref,
                confidence=fd.confidence,
                raw_evidence=fd.raw_evidence,
            )
            session.add(finding_record)

        # 8. Generate grounded AI forensic intelligence briefing
        from app.ai import get_ai_provider
        try:
            ai_provider = get_ai_provider()
            ai_analysis = await ai_provider.generate_analysis(parsed_result, findings_data)
            current_metadata["ai_analysis"] = ai_analysis.model_dump()
        except Exception as e:
            logger.warning(f"Failed to generate AI analysis for case {case_id}: {e}")

        # 9. Compute multi-dimensional risk score, confidence, and coverage
        from app.scoring import RiskScoringEngine
        try:
            score_result = RiskScoringEngine.compute_score(parsed_result, findings_data)
            current_metadata["risk_score"] = {
                "score": score_result.score,
                "confidence": score_result.confidence,
                "coverage": score_result.coverage,
                "uncertainty_label": score_result.uncertainty_label,
                "is_heuristic": True,
                "summary": score_result.summary,
                "breakdown": score_result.breakdown,
            }
        except Exception as e:
            logger.warning(f"Failed to compute risk score for case {case_id}: {e}")

        # 10. Quishing inspection (QR Code matrix decoding)
        from app.enrichment.qr_decoder import QrCodeDecoder
        qr_list: list = []
        try:
            qr_codes = QrCodeDecoder.inspect_attachments(parsed_result.attachments)
            qr_list = [q.to_dict() for q in qr_codes]
            current_metadata["qr_codes"] = qr_list
        except Exception as e:
            logger.warning(f"Failed to inspect QR codes for case {case_id}: {e}")

        # 10. Extract indicators for DB persistence and build Cytoscape.js indicator graph
        from app.graph.builder import IndicatorGraphBuilder
        try:
            db_indicators = IndicatorGraphBuilder.extract_indicators(case.id, parsed_result, qr_list)
            for ind in db_indicators:
                session.add(ind)

            graph = IndicatorGraphBuilder.build_graph(case.id, parsed_result, findings_data, qr_list)
            current_metadata["indicator_graph"] = graph.model_dump()
        except Exception as e:
            logger.warning(f"Failed to build indicator graph for case {case_id}: {e}")

        # 11. Static VBA macro analysis for Office attachments
        from app.forensics.macro_analyzer import VbaMacroAnalyzer
        macro_results_list = []
        try:
            for att in parsed_result.attachments:
                if att.is_macro or att.raw_bytes:
                    res = VbaMacroAnalyzer.analyze_attachment(att.filename, att.raw_bytes, att.sha256)
                    if res.has_macros:
                        macro_results_list.append(res.to_dict())
            current_metadata["macro_analysis"] = macro_results_list
        except Exception as e:
            logger.warning(f"Failed to analyze VBA macros for case {case_id}: {e}")

        # 12. Evasive obfuscation analysis (zero-width, RLO, homoglyphs)
        from app.forensics.obfuscation import ObfuscationAnalyzer
        try:
            body_obf = ObfuscationAnalyzer.analyze_text(parsed_result.body_text or "")
            subj_obf = ObfuscationAnalyzer.analyze_text(parsed_result.headers.get("subject", ""))
            current_metadata["obfuscation_analysis"] = {
                "body": body_obf.to_dict(),
                "subject": subj_obf.to_dict(),
                "has_evasion": body_obf.has_evasion or subj_obf.has_evasion,
            }
        except Exception as e:
            logger.warning(f"Failed to analyze obfuscation for case {case_id}: {e}")

        if parsed_result.mime_depth_exceeded:
            current_metadata["warning"] = "MIME depth exceeded maximum allowed limit"

        # 13. Multi-Class Threat Classification Engine
        from app.scoring.threat_classifier import MultiClassThreatClassifier
        try:
            fd_dicts = [{"title": f.title, "detector": f.detector, "severity": f.severity.value, "detail": f.detail} for f in findings_data]
            threat_class_res = MultiClassThreatClassifier.classify(
                subject=parsed_result.headers.get("subject", ""),
                body_text=parsed_result.body_text or "",
                from_header=from_raw,
                findings=fd_dicts,
                financial_result=current_metadata.get("financial_forensics"),
                macros=current_metadata.get("macro_analysis"),
                obfuscation=current_metadata.get("obfuscation_analysis"),
                dns_validation=current_metadata.get("dns_validation"),
                domain_intel=current_metadata.get("domain_intel"),
                risk_score=(current_metadata.get("risk_score") or {}).get("score", 0.0),
            )
            current_metadata["threat_classification"] = threat_class_res.to_dict()
        except Exception as e:
            logger.warning(f"Failed to classify threat category for case {case_id}: {e}")

        case.metadata_json = current_metadata

        # 14. Transition status to completed
        case.status = CaseStatus.completed

        await session.commit()
        logger.info(f"Case {case_id} processed: parsed structure stored, {len(findings_data)} findings, AI briefing, and risk score computed.")
        return True


def process_case_job(case_id_str: str) -> bool:
    """Entry point for RQ worker."""
    case_id = uuid.UUID(case_id_str)
    return asyncio.run(_async_process_case(case_id))
