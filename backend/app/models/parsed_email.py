"""ParsedEmail model — structured parse output (1:1 with Case)."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, JSON, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ParsedEmail(Base):
    __tablename__ = "parsed_emails"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    headers_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    body_text: Mapped[str | None] = mapped_column(Text)
    body_html: Mapped[str | None] = mapped_column(Text)
    attachments_json: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON)
    urls_json: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON)
    auth_results_json: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    received_chain_json: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON)
    parsed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
