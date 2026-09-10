from pydantic import BaseModel
from typing import Optional, Literal
import uuid

class RiskScoreResponse(BaseModel):
    score: float
    confidence: float
    coverage: float
    uncertainty_label: str
    is_heuristic: Literal[True] = True
    summary: str

class AnalysisStatusResponse(BaseModel):
    case_id: uuid.UUID
    status: str
    progress_pct: Optional[float] = None


class AIAnalysisResponse(BaseModel):
    executive_summary: str
    attack_vector: str
    threat_actor_tactics: list[str]
    recommended_actions: list[str]
    evidence_citations: list[str]
    is_grounded: bool
    provider: str

