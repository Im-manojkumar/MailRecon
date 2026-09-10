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
