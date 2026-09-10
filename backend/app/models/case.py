"""Case model — a single email investigation."""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class CaseStatus(str, enum.Enum):
    pending = "pending"
    processing = "processing"
    completed = "completed"
    failed = "failed"


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), onupdate=func.now()
    )
    status: Mapped[CaseStatus] = mapped_column(
        Enum(CaseStatus), nullable=False, default=CaseStatus.pending
    )
    original_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    original_size: Mapped[int | None] = mapped_column(Integer)
    filename: Mapped[str | None] = mapped_column(String(255))
    storage_key: Mapped[str] = mapped_column(Text, nullable=False)
    analyst_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analysts.id"), nullable=False
    )
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
