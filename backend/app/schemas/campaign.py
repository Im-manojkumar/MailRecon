"""
Pydantic schemas for Threat Actor Campaign Intelligence and Cross-Case Correlation.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class SharedArtifactSchema(BaseModel):
    kind: str
    value: str
    label: str
    occurrences: int
    case_ids: List[str]


class CampaignCaseSummary(BaseModel):
    case_id: str
    filename: str
    created_at: str
    score: float
    threat_category: str
    category_label: str
    from_email: str
    from_domain: str
    recipient: str
    subject: str
    orig_ip: Optional[str] = None


class CampaignListItem(BaseModel):
    campaign_id: str
    name: str
    threat_category: str
    threat_archetype: str
    risk_score: float
    confidence: float
    first_seen: str
    last_seen: str
    case_count: int
    tactics: List[str] = []
    description: str


class CampaignListResponse(BaseModel):
    items: List[CampaignListItem]
    total: int


class CampaignDetail(CampaignListItem):
    cases: List[Dict[str, Any]] = []
    shared_artifacts: List[Dict[str, Any]] = []
    graph: Dict[str, Any] = {"nodes": [], "edges": []}


class CaseCampaignAffiliation(BaseModel):
    case_id: str
    is_part_of_campaign: bool
    campaign_id: Optional[str] = None
    campaign_name: Optional[str] = None
    threat_archetype: Optional[str] = None
    total_correlated_cases: int = 1
    shared_artifacts: List[Dict[str, Any]] = []
    affiliated_cases: List[Dict[str, Any]] = []
    graph: Optional[Dict[str, Any]] = None
