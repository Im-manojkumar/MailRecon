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

        # 5. Run deterministic security detectors and persist findings
        from app.detectors import run_all_detectors
        from app.models.finding import Finding
        
        findings_data = run_all_detectors(parsed_result)
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

        # 6. Generate grounded AI forensic intelligence briefing
        from app.ai import get_ai_provider
        current_metadata = dict(case.metadata_json or {})
        try:
            ai_provider = get_ai_provider()
            ai_analysis = await ai_provider.generate_analysis(parsed_result, findings_data)
            current_metadata["ai_analysis"] = ai_analysis.model_dump()
        except Exception as e:
            logger.warning(f"Failed to generate AI analysis for case {case_id}: {e}")

        if parsed_result.mime_depth_exceeded:
            current_metadata["warning"] = "MIME depth exceeded maximum allowed limit"

        case.metadata_json = current_metadata

        # 7. Transition status to completed
        case.status = CaseStatus.completed

        await session.commit()
        logger.info(f"Case {case_id} processed: parsed structure stored, {len(findings_data)} findings, and AI briefing generated.")
        return True


def process_case_job(case_id_str: str) -> bool:
    """Entry point for RQ worker."""
    case_id = uuid.UUID(case_id_str)
    return asyncio.run(_async_process_case(case_id))
