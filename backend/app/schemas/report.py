from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime
import uuid
from app.models.report import ReportFormat

class ReportResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    format: ReportFormat
    integrity_sha256: Optional[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ReportListResponse(BaseModel):
    items: list[ReportResponse]
    total: int
