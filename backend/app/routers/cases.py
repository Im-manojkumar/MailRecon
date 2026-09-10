import hashlib
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_analyst
from app.config import settings
from app.database import get_db
from app.models.case import Case, CaseStatus
from app.models.finding import Finding
from app.models.parsed_email import ParsedEmail
from app.schemas.analysis import RiskScoreResponse
from app.schemas.case import CaseDetail, CaseListResponse, CaseResponse
from app.schemas.finding import FindingListResponse
from app.schemas.parsed_email import ParsedEmailResponse
from app.storage.base import EvidenceStore
from app.storage.deps import get_evidence_store
from app.tasks.queue import enqueue_case_analysis

router = APIRouter()


async def get_case_or_404(case_id: uuid.UUID, analyst_id: uuid.UUID, db: AsyncSession) -> Case:
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalars().first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if case.analyst_id != analyst_id:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
async def create_case(
    file: UploadFile = File(...),
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
    storage: EvidenceStore = Depends(get_evidence_store),
):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted")

    content = await file.read()

    # Enforce maximum upload size
    if len(content) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_BYTES} bytes",
        )

    # Compute SHA-256 digest
    sha256_hash = hashlib.sha256(content).hexdigest()
    storage_key = f"cases/{sha256_hash}.eml"

    # Store byte-for-byte evidence in immutable storage
    await storage.put(storage_key, content)

    new_case = Case(
        original_sha256=sha256_hash,
        original_size=len(content),
        filename=file.filename,
        storage_key=storage_key,
        analyst_id=analyst_id,
        status=CaseStatus.pending,
    )

    db.add(new_case)
    await db.commit()
    await db.refresh(new_case)

    # Enqueue background analysis job
    enqueue_case_analysis(new_case.id)

    return new_case


@router.get("", response_model=CaseListResponse)
async def list_cases(
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Case).where(Case.analyst_id == analyst_id))
    items = result.scalars().all()
    return {"items": items, "total": len(items)}


@router.get("/{id}", response_model=CaseDetail)
async def get_case(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    return case


@router.get("/{id}/parsed", response_model=ParsedEmailResponse)
async def get_parsed_email(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    result = await db.execute(select(ParsedEmail).where(ParsedEmail.case_id == case.id))
    parsed_email = result.scalars().first()
    if not parsed_email:
        raise HTTPException(status_code=404, detail="Email has not been parsed yet")
    return parsed_email


@router.get("/{id}/attachments/{sha256}")
async def get_attachment_file(
    id: uuid.UUID,
    sha256: str,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
    storage: EvidenceStore = Depends(get_evidence_store),
):
    case = await get_case_or_404(id, analyst_id, db)

    result = await db.execute(select(ParsedEmail).where(ParsedEmail.case_id == case.id))
    parsed = result.scalars().first()
    if not parsed or not parsed.attachments_json:
        raise HTTPException(status_code=404, detail="Attachment not found")

    attachment_entry = None
    for att in parsed.attachments_json:
        if att.get("sha256") == sha256:
            attachment_entry = att
            break

    if not attachment_entry:
        raise HTTPException(status_code=404, detail="Attachment not found in case")

    storage_key = attachment_entry.get("storage_key") or f"cases/{case.original_sha256}/attachments/{sha256}"
    if not await storage.exists(storage_key):
        raise HTTPException(status_code=404, detail="Attachment file not found in storage")

    stream = storage.get_stream(storage_key)
    safe_filename = attachment_entry.get("filename", "attachment.bin").replace('"', '\\"')
    headers = {
        # Never trust declared MIME to avoid browser script execution (Security requirement)
        "Content-Disposition": f'attachment; filename="{safe_filename}"',
        "X-Attachment-SHA256": sha256,
        "X-Content-Type-Options": "nosniff",
    }
    return StreamingResponse(stream, media_type="application/octet-stream", headers=headers)


@router.get("/{id}/findings", response_model=FindingListResponse)
async def get_findings(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    case = await get_case_or_404(id, analyst_id, db)
    result = await db.execute(select(Finding).where(Finding.case_id == case.id).order_by(Finding.created_at))
    items = result.scalars().all()
    return {"items": items, "total": len(items)}


@router.get("/{id}/indicators")
async def get_indicators(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    await get_case_or_404(id, analyst_id, db)
    return []


@router.get("/{id}/graph")
async def get_indicator_graph(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    await get_case_or_404(id, analyst_id, db)
    return {"nodes": [], "edges": []}


@router.get("/{id}/score", response_model=RiskScoreResponse)
async def get_risk_score(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    await get_case_or_404(id, analyst_id, db)
    return {
        "score": 0.0,
        "confidence": 0.0,
        "coverage": 0.0,
        "uncertainty_label": "not_yet_analyzed",
        "is_heuristic": True,
        "summary": "Case has not been analyzed yet.",
    }


@router.post("/{id}/report", status_code=status.HTTP_202_ACCEPTED)
async def generate_report(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    await get_case_or_404(id, analyst_id, db)
    return {"message": "Report generation started"}


@router.get("/{id}/reports")
async def list_reports(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    await get_case_or_404(id, analyst_id, db)
    return []


@router.get("/{id}/reports/{rid}")
async def download_report(
    id: uuid.UUID,
    rid: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    await get_case_or_404(id, analyst_id, db)
    raise HTTPException(status_code=404, detail="Report not found")


@router.get("/{id}/original")
async def get_original_file(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
    storage: EvidenceStore = Depends(get_evidence_store),
):
    case = await get_case_or_404(id, analyst_id, db)

    if not await storage.exists(case.storage_key):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence file not found in storage",
        )

    # Runtime SHA-256 integrity verification (Mitigating Threat T03)
    is_valid = await storage.verify_integrity(case.storage_key, case.original_sha256)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Evidence integrity violation: stored file hash does not match original SHA-256",
        )

    stream = storage.get_stream(case.storage_key)
    safe_filename = (case.filename or "evidence.eml").replace('"', '\\"')
    headers = {
        "Content-Disposition": f'attachment; filename="{safe_filename}"',
        "X-Evidence-SHA256": case.original_sha256,
    }
    return StreamingResponse(stream, media_type="message/rfc822", headers=headers)
