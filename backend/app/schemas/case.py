"""Pydantic schemas for Case API responses."""

from datetime import datetime
from typing import Any, Optional
import uuid

from pydantic import BaseModel, ConfigDict

from app.models.case import CaseStatus


class CaseResponse(BaseModel):
    id: uuid.UUID
    status: CaseStatus
    original_sha256: str
    original_size: Optional[int] = None
    filename: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class CaseDetail(CaseResponse):
    analyst_id: uuid.UUID
    metadata_json: Optional[dict[str, Any]] = None


class CaseListResponse(BaseModel):
    items: list[CaseResponse]
    total: int
