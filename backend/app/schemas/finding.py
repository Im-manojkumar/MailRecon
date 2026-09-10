from pydantic import BaseModel, ConfigDict
from typing import Optional, Any
from datetime import datetime
import uuid
from app.models.finding import SeverityLevel

class FindingResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    detector: str
    severity: SeverityLevel
    title: Optional[str]
    detail: Optional[str]
    evidence_ref: Optional[str]
    confidence: Optional[float]
    raw_evidence: Optional[dict[str, Any]]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total: int
