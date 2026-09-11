"""
API endpoints for Threat Actor Campaign Correlation and Multi-Case Intelligence.
"""
from typing import Any, Dict, List
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_analyst
from app.correlation.campaign_clusterer import CampaignClusterer
from app.database import get_db
from app.models.case import Case
from app.models.parsed_email import ParsedEmail
from app.schemas.campaign import (
    CampaignDetail,
    CampaignListItem,
    CampaignListResponse,
    CaseCampaignAffiliation,
)

router = APIRouter()


async def _load_all_cases_with_data(db: AsyncSession, analyst_id: uuid.UUID) -> List[Dict[str, Any]]:
    """
    Loads all cases and associated parsed emails for the analyst.
    """
    stmt = (
        select(Case, ParsedEmail)
        .outerjoin(ParsedEmail, Case.id == ParsedEmail.case_id)
        .where(Case.analyst_id == analyst_id)
        .order_by(Case.created_at.desc())
    )
    result = await db.execute(stmt)
    rows = result.all()

    case_records = []
    for case, parsed in rows:
        case_dict = {
            "id": str(case.id),
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "filename": case.filename or f"Case_{str(case.id)[:8]}",
            "original_sha256": case.original_sha256,
            "metadata_json": case.metadata_json or {},
            "parsed_email": {
                "headers_json": parsed.headers_json if parsed else {},
                "attachments_json": parsed.attachments_json if parsed else [],
                "urls_json": parsed.urls_json if parsed else [],
                "body_text": parsed.body_text if parsed else "",
            }
            if parsed
            else {},
        }
        case_records.append(case_dict)

    return case_records


@router.get("", response_model=CampaignListResponse)
async def list_campaigns(
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    """
    Evaluates cross-case infrastructure reuse and returns active threat actor campaigns.
    """
    case_records = await _load_all_cases_with_data(db, analyst_id)
    clusters = CampaignClusterer.cluster_cases(case_records)

    items = [
        CampaignListItem(
            campaign_id=c.campaign_id,
            name=c.name,
            threat_category=c.threat_category,
            threat_archetype=c.threat_archetype,
            risk_score=c.risk_score,
            confidence=c.confidence,
            first_seen=c.first_seen,
            last_seen=c.last_seen,
            case_count=c.case_count,
            tactics=c.tactics,
            description=c.description,
        )
        for c in clusters
    ]

    return CampaignListResponse(items=items, total=len(items))


@router.get("/{campaign_id}", response_model=CampaignDetail)
async def get_campaign_detail(
    campaign_id: str,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns detailed campaign intelligence including interconnected graph and member cases.
    """
    case_records = await _load_all_cases_with_data(db, analyst_id)
    clusters = CampaignClusterer.cluster_cases(case_records)

    target_campaign = next((c for c in clusters if c.campaign_id == campaign_id), None)
    if not target_campaign:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign '{campaign_id}' not found or has been disbanded.",
        )

    return CampaignDetail(
        campaign_id=target_campaign.campaign_id,
        name=target_campaign.name,
        threat_category=target_campaign.threat_category,
        threat_archetype=target_campaign.threat_archetype,
        risk_score=target_campaign.risk_score,
        confidence=target_campaign.confidence,
        first_seen=target_campaign.first_seen,
        last_seen=target_campaign.last_seen,
        case_count=target_campaign.case_count,
        tactics=target_campaign.tactics,
        description=target_campaign.description,
        cases=target_campaign.cases,
        shared_artifacts=target_campaign.shared_artifacts,
        graph=target_campaign.graph,
    )


@router.get("/by-case/{case_id}", response_model=CaseCampaignAffiliation)
async def get_case_campaign_affiliation(
    case_id: uuid.UUID,
    analyst_id: uuid.UUID = Depends(get_current_analyst),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns the campaign cluster (if any) affiliated with a specific case.
    """
    cid_str = str(case_id)
    case_records = await _load_all_cases_with_data(db, analyst_id)
    clusters = CampaignClusterer.cluster_cases(case_records)

    for c in clusters:
        case_ids_in_camp = [cs["case_id"] for cs in c.cases]
        if cid_str in case_ids_in_camp:
            affiliated = [cs for cs in c.cases if cs["case_id"] != cid_str]
            # Filter shared artifacts relevant to this case
            case_shared = [
                art for art in c.shared_artifacts if cid_str in art.get("case_ids", [])
            ]
            return CaseCampaignAffiliation(
                case_id=cid_str,
                is_part_of_campaign=True,
                campaign_id=c.campaign_id,
                campaign_name=c.name,
                threat_archetype=c.threat_archetype,
                total_correlated_cases=c.case_count,
                shared_artifacts=case_shared or c.shared_artifacts,
                affiliated_cases=affiliated,
                graph=c.graph,
            )

    return CaseCampaignAffiliation(
        case_id=cid_str,
        is_part_of_campaign=False,
        total_correlated_cases=1,
        shared_artifacts=[],
        affiliated_cases=[],
    )
