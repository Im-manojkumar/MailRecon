from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime
import uuid
from app.models.indicator import IndicatorKind

class IndicatorResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    kind: IndicatorKind
    value: str
    context: Optional[str]
    first_seen_at: datetime

    model_config = ConfigDict(from_attributes=True)

class IndicatorListResponse(BaseModel):
    items: list[IndicatorResponse]
    total: int

class GraphNode(BaseModel):
    id: str
    kind: str
    value: str
    label: str
    risk_level: Optional[str] = "neutral"
    metadata: Optional[dict] = None


class GraphEdge(BaseModel):
    id: Optional[str] = None
    source: str
    target: str
    relationship: str
    label: Optional[str] = None


class IndicatorGraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
