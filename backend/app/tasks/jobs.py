import asyncio
import logging
import uuid

from sqlalchemy import select

from app.database import async_session_maker
from app.models.case import Case, CaseStatus
from app.storage.deps import get_evidence_store

logger = logging.getLogger(__name__)


async def _async_process_case(case_id: uuid.UUID) -> bool:
    """Async implementation of case ingestion and integrity verification."""
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

        # Verify evidence existence and SHA-256 integrity
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

        logger.info(f"Case {case_id} evidence verified (SHA-256: {case.original_sha256}). Ready for parser.")
        # In Phase 1, the evidence is successfully ingested and verified.
        # Future phases will run the parser, detectors, and scoring here.
        return True


def process_case_job(case_id_str: str) -> bool:
    """Entry point for RQ worker."""
    case_id = uuid.UUID(case_id_str)
    return asyncio.run(_async_process_case(case_id))
