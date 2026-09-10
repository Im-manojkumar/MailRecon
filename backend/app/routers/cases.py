from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func
import uuid
import hashlib

from app.database import get_db
from app.auth import get_current_analyst
from app.models.case import Case, CaseStatus
from app.schemas.case import CaseResponse, CaseDetail, CaseListResponse
from app.schemas.analysis import RiskScoreResponse

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
    db: AsyncSession = Depends(get_db)
):
    if not file.filename.endswith('.eml'):
        raise HTTPException(status_code=400, detail="File must be an .eml file")
        
    content = await file.read()
    
    # In a real app, check MAX_UPLOAD_BYTES here
    
    sha256_hash = hashlib.sha256(content).hexdigest()
    
    # Store file locally (stubbed out for now, should use storage component)
    storage_key = f"cases/{sha256_hash}.eml"
    
    new_case = Case(
        original_sha256=sha256_hash,
        original_size=len(content),
        filename=file.filename,
        storage_key=storage_key,
        analyst_id=analyst_id,
        status=CaseStatus.pending
    )
    
    db.add(new_case)
    await db.commit()
    await db.refresh(new_case)
    
    return new_case

@router.get("", response_model=CaseListResponse)
async def list_cases(
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Case).where(Case.analyst_id == analyst_id))
    items = result.scalars().all()
    # Pydantic v2 requires from_attributes or converting to dict. 
    # Actually CaseListResponse handles it if models have ConfigDict(from_attributes=True)
    return {"items": items, "total": len(items)}

@router.get("/{id}", response_model=CaseDetail)
async def get_case(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    case = await get_case_or_404(id, analyst_id, db)
    return case

@router.get("/{id}/parsed")
async def get_parsed_email(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    await get_case_or_404(id, analyst_id, db)
    raise HTTPException(status_code=404, detail="Not yet parsed")

@router.get("/{id}/findings")
async def get_findings(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    await get_case_or_404(id, analyst_id, db)
    return []

@router.get("/{id}/indicators")
async def get_indicators(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    await get_case_or_404(id, analyst_id, db)
    return []

@router.get("/{id}/graph")
async def get_indicator_graph(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    await get_case_or_404(id, analyst_id, db)
    return {"nodes": [], "edges": []}

@router.get("/{id}/score", response_model=RiskScoreResponse)
async def get_risk_score(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    await get_case_or_404(id, analyst_id, db)
    return {
        "score": 0.0,
        "confidence": 0.0,
        "coverage": 0.0,
        "uncertainty_label": "not_yet_analyzed",
        "is_heuristic": True,
        "summary": "Case has not been analyzed yet."
    }

@router.post("/{id}/report", status_code=status.HTTP_202_ACCEPTED)
async def generate_report(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    await get_case_or_404(id, analyst_id, db)
    return {"message": "Report generation started"}

@router.get("/{id}/reports")
async def list_reports(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    await get_case_or_404(id, analyst_id, db)
    return []

@router.get("/{id}/reports/{rid}")
async def download_report(
    id: uuid.UUID,
    rid: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    await get_case_or_404(id, analyst_id, db)
    raise HTTPException(status_code=404, detail="Report not found")

@router.get("/{id}/original")
async def get_original_file(
    id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db)
):
    await get_case_or_404(id, analyst_id, db)
    # Stubbed streaming response
    return StreamingResponse(iter([]), media_type="message/rfc822")
